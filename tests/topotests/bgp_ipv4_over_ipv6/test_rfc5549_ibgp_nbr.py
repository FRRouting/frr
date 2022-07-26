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
    addKernelRoute,
    write_test_footer,
    create_prefix_lists,
    verify_rib,
    create_static_routes,
    reset_config_on_routers,
    step,
    create_route_maps,
    get_frr_ipv6_linklocal,
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
NETWORK_CMD_IP = "1.0.1.17/32"
NO_OF_RTES = 2
TOPOOLOGY = """
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
"""

TESTCASES = """
1. Verify IPv4 and IPv6 routes advertise using "redistribute static"
 and "network command" are received on IBGP peer with IPv6 nexthop
2. Verify IPv4 routes are advertised and withdrawn when IPv6 IBGP session
 established using loopback interface
3. Verify IPv4 routes are advertised to peer when static routes are
 configured with ADMIN distance and tag option
4. Verify IPv4 routes advertised to peer when BGP session established
 using link-local address
 """


def setup_module(mod):
    """Set up the pytest environment."""

    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/rfc5549_ibgp_nbr.json".format(CWD)
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


def test_ext_nh_cap_red_static_network_ibgp_peer_p1(request):
    """

    Test extended capability nexthop with ibgp peer.

    Verify IPv4 and IPv6 routes advertise using "redistribute static"
    and "network command" are received on IBGP peer with IPv6 nexthop
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    step(
        "Configure IPv6 EBGP session between R1 and R2 with global IPv6"
        " address Enable capability extended-nexthop on the nbr from both"
        " the routers"
    )
    step(
        "Change ebgp to ibgp nbrs between r1 and r2 , Activate same IPv6"
        " nbr from IPv4 unicast family "
    )

    step(
        " Configure 5 IPv4 static routes"
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
    # this test case needs ipv6 routes to be configured
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

    glip = get_llip("r1", "r2-link0")
    assert glip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 and IPv6 routes advertised using static & network command are"
        "received on R2 BGP and routing table , verify using show ip bgp"
        "show ip route  for IPv4 routes and show bgp, show ipv6 routes"
        "for IPv6 routes ."
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
                    "next_hop": glip,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify IPv4 routes are installed with IPv6 global nexthop of R1"
        "R1 to R2 connected link"
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

    write_test_footer(tc_name)


def test_ext_nh_cap_admin_dist_tag_ibgp_peer_p1(request):
    """

    Test extended capability nexthop with admin distance and route tag.

    Verify IPv4 routes are advertised to peer when static routes
    are configured with ADMIN distance and tag option
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    reset_config_on_routers(tgen)
    step(
        "Configure IPv6 EBGP session between R1 and R2 with global IPv6"
        " address Enable capability extended-nexthop on the nbr from both"
        " the routers"
    )
    step(
        "Change ebgp to ibgp nbrs between r1 and r2 , Activate same IPv6"
        " nbr from IPv4 unicast family "
    )
    step(
        " Configure 5 IPv4 static routes"
        " on R1 nexthop for static route exists on different link of R0"
    )
    count = 0
    for rte in range(0, NO_OF_RTES):
        count += 1
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][rte],
                        "no_of_ip": 1,
                        "next_hop": NEXT_HOP["ipv4"][rte],
                        "admin_distance": 100 + count,
                        "tag": 4001 + count,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step(
        "Advertise static routes from IPv4 unicast family & IPv6 unicast"
        " family respectively from R1.Configure loopback on R1 with IPv4 "
        "address & Advertise loopback from IPv4 unicast family "
        "using network cmd from R1"
    )
    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}}
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    glip = get_llip("r1", "r2-link0")
    assert glip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 and IPv6 routes advertised using static & network cmd are"
        "received on R2 BGP and routing table , verify using show ip bgp"
        "show ip route  for IPv4 routes and show bgp, show ipv6 routes"
        "for IPv6 routes ."
    )

    dut = "r2"
    protocol = "bgp"
    count = 0
    # verify the routes with nh as ext_nh
    verify_nh_for_static_rtes = {
        "r1": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": NO_OF_RTES,
                    "next_hop": glip,
                    "admin_distance": 100 + count,
                    "tag": 4001 + count,
                }
            ]
        }
    }
    bgp_rib = verify_bgp_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glip
    )
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_static_rtes, next_hop=glip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    count = 0
    for rte in range(0, NO_OF_RTES):
        count += 10
        input_dict_2 = {
            "r3": {
                "prefix_lists": {
                    "ipv4": {
                        "pf_list_1_ipv4": [
                            {
                                "seqid": 0 + count,
                                "action": "permit",
                                "network": NETWORK["ipv4"][rte],
                            }
                        ]
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n " "Error: {}".format(
            tc_name, result
        )

        # Create route map
        input_dict_6 = {
            "r3": {
                "route_maps": {
                    "rmap_match_tag_1_{}".format("ipv4"): [
                        {
                            "action": "deny",
                            "match": {
                                "ipv4": {"prefix_lists": "pf_list_1_{}".format("ipv4")}
                            },
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        # Configure neighbor for route map
        input_dict_7 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link0": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_match_tag_1_ipv4",
                                                        "direction": "out",
                                                    }
                                                ]
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

        result = create_router_bgp(tgen, topo, input_dict_7)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_ibgp_loopback_nbr_p1(request):
    """
    Verify Extended capability nexthop with loopback interface.

    Verify IPv4 routes are advertised and withdrawn when IPv6 IBGP
    session established using loopback interface
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    global topo
    topo1 = deepcopy(topo)
    reset_config_on_routers(tgen)
    step("Configure IPv6 global address between R1 and R2")
    step(
        "Configure loopback on R1 and R2 and establish EBGP session "
        "between R1 and R2 over loopback global ip"
    )
    step("Configure static route on R1 and R2 for loopback reachability")
    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")

    for routerN in ["r1", "r2"]:
        for addr_type in ["ipv6"]:
            for bgp_neighbor in topo1["routers"][routerN]["bgp"]["address_family"][
                addr_type
            ]["unicast"]["neighbor"].keys():
                # Adding ['source_link'] = 'lo' key:value pair
                if bgp_neighbor == "r1" or bgp_neighbor == "r2":
                    topo1["routers"][routerN]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]["neighbor"][bgp_neighbor]["dest_link"] = {
                        "lo": {
                            "source_link": "lo",
                            "ebgp_multihop": 2,
                            "capability": "extended-nexthop",
                            "activate": "ipv4",
                        }
                    }
    # Creating configuration from JSON
    build_config_from_json(tgen, topo1, save_bkup=False)

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {"r1-link0": {"deactivate": "ipv6"}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {"r2-link0": {"deactivate": "ipv6"}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {"r1-link0": {"deactivate": "ipv4"}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {"r2-link0": {"deactivate": "ipv4"}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    r2_lo_v4 = topo["routers"]["r2"]["links"]["lo"]["ipv4"]
    r2_lo_v6 = topo["routers"]["r2"]["links"]["lo"]["ipv6"]
    r1_lo_v4 = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    r1_lo_v6 = topo["routers"]["r1"]["links"]["lo"]["ipv6"]
    r1_r2_intf = topo["routers"]["r1"]["links"]["r2-link0"]["interface"]
    r2_r1_intf = topo["routers"]["r2"]["links"]["r1-link0"]["interface"]

    r1_r2_v6_nh = topo["routers"]["r1"]["links"]["r2-link0"]["ipv6"].split("/")[0]
    r2_r1_v6_nh = topo["routers"]["r2"]["links"]["r1-link0"]["ipv6"].split("/")[0]

    ipv4_list = [("r1", r1_r2_intf, [r2_lo_v4]), ("r2", r2_r1_intf, [r1_lo_v4])]

    ipv6_list = [
        ("r1", r1_r2_intf, [r2_lo_v6], r2_r1_v6_nh),
        ("r2", r2_r1_intf, [r1_lo_v6], r1_r2_v6_nh),
    ]

    for dut, intf, loop_addr in ipv4_list:
        result = addKernelRoute(tgen, dut, intf, loop_addr)
        # assert result is True, "Testcase {}:Failed \n Error: {}". \
        #    format(tc_name, result)

    for dut, intf, loop_addr, next_hop in ipv6_list:
        result = addKernelRoute(tgen, dut, intf, loop_addr, next_hop)
        # assert result is True, "Testcase {}:Failed \n Error: {}". \
        #    format(tc_name, result)

    r2_lo_v4 = topo["routers"]["r2"]["links"]["lo"]["ipv4"]
    r2_lo_v6 = topo["routers"]["r2"]["links"]["lo"]["ipv6"]
    r1_lo_v4 = topo["routers"]["r1"]["links"]["lo"]["ipv4"]
    r1_lo_v6 = topo["routers"]["r1"]["links"]["lo"]["ipv6"]
    r1_r2_intf = topo["routers"]["r1"]["links"]["r2-link0"]["interface"]
    r2_r1_intf = topo["routers"]["r2"]["links"]["r1-link0"]["interface"]

    r1_r2_v6_nh = topo["routers"]["r1"]["links"]["r2-link0"]["ipv6"].split("/")[0]
    r2_r1_v6_nh = topo["routers"]["r2"]["links"]["r1-link0"]["ipv6"].split("/")[0]

    r1_r2_v4_nh = topo["routers"]["r1"]["links"]["r2-link0"]["ipv4"].split("/")[0]
    r2_r1_v4_nh = topo["routers"]["r2"]["links"]["r1-link0"]["ipv4"].split("/")[0]

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": r2_lo_v4, "next_hop": r2_r1_v4_nh},
                {"network": r2_lo_v6, "next_hop": r2_r1_v6_nh},
            ]
        },
        "r2": {
            "static_routes": [
                {"network": r1_lo_v4, "next_hop": r1_r2_v4_nh},
                {"network": r1_lo_v6, "next_hop": r1_r2_v6_nh},
            ]
        },
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call verify whether BGP is converged
    result = verify_bgp_convergence(tgen, topo1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Enable cap ext nh on r1 and r2 and activate in ipv4 addr family")
    configure_bgp_on_r1 = {
        "r1": {
            "default_ipv4_unicast": False,
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "lo": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r2 = {
        "r2": {
            "default_ipv4_unicast": False,
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "lo": {
                                            "activate": "ipv4",
                                            "capability": "extended-nexthop",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp convergence.")
    bgp_convergence = verify_bgp_convergence(tgen, topo1)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Configure 2 IPv4 static" " routes on R1, Nexthop as different links of R0")

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
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "IPv4 routes advertised using static and network command are "
        " received on R2 BGP and routing table , "
        "verify using show ip bgp, show ip route for IPv4 routes ."
    )

    gllip = (topo1["routers"]["r1"]["links"]["lo"]["ipv6"].split("/")[0]).lower()
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

    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": gllip}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Remove IPv4 routes advertised using network command"
        " from R1 and advertise again"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static"}],
                            "advertise_networks": [
                                {
                                    "network": NETWORK_CMD_IP,
                                    "no_of_network": 1,
                                    "delete": True,
                                }
                            ],
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static"}],
                            "advertise_networks": [
                                {
                                    "network": NETWORK_CMD_IP,
                                    "no_of_network": 1,
                                }
                            ],
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "After removing IPv4 routes from network command , routes which are "
        "advertised using redistribute static are still present in the on "
        "R2 , verify using show ip bgp and show ip route"
    )

    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": gllip}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Remove IPv4 routes advertised using redistribute static"
        " command from R1 and advertise again"
    )

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    configure_bgp_on_r1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}}
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo1, configure_bgp_on_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "After removing IPv4 routes from redistribute static , routes which"
        " are advertised using network are still present in the on R2 , "
        "verify using show ip bgp and show ip route"
    )

    verify_nh_for_nw_rtes = {
        "r1": {
            "static_routes": [
                {"network": NETWORK_CMD_IP, "no_of_ip": 1, "next_hop": gllip}
            ]
        }
    }
    bgp_rib = verify_bgp_rib(tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip)
    assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(tc_name, bgp_rib)
    result = verify_rib(
        tgen, "ipv4", dut, verify_nh_for_nw_rtes, next_hop=gllip, protocol=protocol
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
