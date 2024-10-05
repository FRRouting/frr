#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
#                       Shreenidhi A R <rshreenidhi@vmware.com>
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#
"""
Following tests are covered.
1. Verify default-originate route with default static and network command
2. Verify default-originate route with aggregate summary command
3. Verfiy  default-originate behaviour in ecmp
"""
import os
import sys
import time
import pytest
import datetime
from lib.topolog import logger
from time import sleep

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger
from lib import topotest

from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    get_dut_as_number,
    verify_rib_default_route,
    verify_fib_default_route,
)
from lib.common_config import (
    verify_fib_routes,
    step,
    create_prefix_lists,
    run_frr_cmd,
    create_route_maps,
    shutdown_bringup_interface,
    get_frr_ipv6_linklocal,
    start_topology,
    apply_raw_config,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    check_router_status,
)

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers

# Global variables
topo = None
NETWORK1_1 = {"ipv4": "198.51.1.1/32", "ipv6": "2001:DB8::1:1/128"}
NETWORK1_2 = {"ipv4": "198.51.1.2/32", "ipv6": "2001:DB8::1:2/128"}
NETWORK1_3 = {"ipv4": "198.51.1.3/32", "ipv6": "2001:DB8::1:3/128"}
NETWORK1_4 = {"ipv4": "198.51.1.4/32", "ipv6": "2001:DB8::1:4/128"}
NETWORK1_5 = {"ipv4": "198.51.1.5/32", "ipv6": "2001:DB8::1:5/128"}

ipv4_uptime_dict = {
    "r2": {
        "static_routes": [
            {"network": "0.0.0.0/0"},
        ]
    }
}

ipv6_uptime_dict = {
    "r2": {
        "static_routes": [
            {"network": "::/0"},
        ]
    }
}

DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_default_originate_2links.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    global BGP_CONVERGENCE
    global DEFAULT_ROUTES
    global DEFAULT_ROUTE_NXT_HOP_LINK1, DEFAULT_ROUTE_NXT_HOP_LINK2
    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    interface = topo["routers"]["r1"]["links"]["r2-link1"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2-link1"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2-link1"]["ipv6"].split("/")[0]
    DEFAULT_ROUTE_NXT_HOP_LINK1 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}

    interface = topo["routers"]["r1"]["links"]["r2-link2"]["interface"]
    ipv6_link_local = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
    ipv4_nxt_hop = topo["routers"]["r1"]["links"]["r2-link2"]["ipv4"].split("/")[0]
    ipv6_nxt_hop = topo["routers"]["r1"]["links"]["r2-link2"]["ipv6"].split("/")[0]
    DEFAULT_ROUTE_NXT_HOP_LINK2 = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local}
    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#                      Local API's
#
#####################################################


def get_rib_route_uptime(tgen, addr_type, dut, input_dict):
    """
    Verify route uptime in RIB using "show ip route"

    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict` : input dict, has details of static routes
    * `route_uptime`: uptime of the routes

    Usage
    -----
    # Creating static routes for r1
     input_dict_r1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": "147.10.13.4/32"
                    },
                   {
                       "network": "147.10.12.0/24"
                   },
                    {
                        "network": "147.10.13.4/32"
                    },
                   {
                       "network": "147.10.13.4/32"
                   },
                   {
                       "network": "147.10.13.4/32"
                   }
                ]
            }
    }


    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: get_rib_route_uptime()")
    route_time = []
    router_list = tgen.routers()
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue

            logger.info("Checking router %s RIB:", router)

            # Verifying RIB routes
            if addr_type == "ipv4":
                command = "show ip route"
            else:
                command = "show ipv6 route"

            if "static_routes" in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    if "vrf" in static_route and static_route["vrf"] is not None:
                        logger.info(
                            "[DUT: {}]: Verifying routes for VRF:"
                            " {}".format(router, static_route["vrf"])
                        )
                        cmd = "{} vrf {}".format(command, static_route["vrf"])

                    else:
                        cmd = "{}".format(command)

                    cmd = "{} json".format(cmd)

                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                    if bool(rib_routes_json) is False:
                        errormsg = "No route found in rib of router {}..".format(router)
                        return errormsg
                    network = static_route["network"]
                    route_time.append(rib_routes_json[network][0]["uptime"])

    logger.info("Exiting lib API: get_rib_route_uptime()")
    return route_time


def verify_the_uptime(time_stamp_before, time_stamp_after, incremented=None):
    """
    time_stamp_before : string the time stamp captured
    time_stamp_after : string the time stamp captured
    """
    uptime_before = datetime.datetime.strptime(time_stamp_before[0], "%H:%M:%S")
    uptime_after = datetime.datetime.strptime(time_stamp_after[0], "%H:%M:%S")

    if incremented == True:
        if uptime_before < uptime_after:
            logger.info(
                "  The Uptime before [{}] is less than [{}].......PASSED ".format(
                    time_stamp_before, time_stamp_after
                )
            )
            return True
        else:
            logger.error(
                "  The Uptime before [{}] is greater than the uptime after [{}].......FAILED ".format(
                    time_stamp_before, time_stamp_after
                )
            )
            return False
    else:
        logger.info(
            "  The Uptime before [{}] the same as after [{}] ".format(
                time_stamp_before, time_stamp_after
            )
        )
        return True


def get_best_path_route_in_FIB(tgen, topo, dut, network):
    """
    API to verify the best route in FIB and return the ipv4 and ipv6 nexthop for the given route
    command
    =======
    show ip route
    show ipv6 route
    params
    ======
    dut : device under test :
    network ; route (ip) to which the best route to be retrieved
    Returns
    ========
    on success : return dict with next hops for the best hop
    on failure : return error message with boolean False
    """
    is_ipv4_best_path_found = False
    rnode = tgen.routers()[dut]
    ipv4_show_bgp_json = run_frr_cmd(rnode, "sh ip bgp  json ", isjson=True)
    ipv6_show_bgp_json = run_frr_cmd(
        rnode, "sh ip bgp ipv6 unicast  json ", isjson=True
    )
    output_dict = {"ipv4": None, "ipv6": None}
    ipv4_nxt_hop_count = len(ipv4_show_bgp_json["routes"][network["ipv4"]])
    for index in range(ipv4_nxt_hop_count):
        if "bestpath" in ipv4_show_bgp_json["routes"][network["ipv4"]][index].keys():
            best_path_ip = ipv4_show_bgp_json["routes"][network["ipv4"]][index][
                "nexthops"
            ][0]["ip"]
            output_dict["ipv4"] = best_path_ip
            logger.info(
                "[DUT [{}]] Best path for the route {} is  {} ".format(
                    dut, network["ipv4"], best_path_ip
                )
            )
            is_ipv4_best_path_found = True
        else:
            logger.error("ERROR....! No Best Path  Found in BGP RIB.... FAILED")

    ipv6_nxt_hop_count = len(ipv6_show_bgp_json["routes"][network["ipv6"]])
    for index in range(ipv6_nxt_hop_count):
        if "bestpath" in ipv6_show_bgp_json["routes"][network["ipv6"]][index].keys():
            ip_add_count = len(
                ipv6_show_bgp_json["routes"][network["ipv6"]][index]["nexthops"]
            )
            for i_index in range(ip_add_count):
                if (
                    "global"
                    in ipv6_show_bgp_json["routes"][network["ipv6"]][index]["nexthops"][
                        i_index
                    ]["scope"]
                ):
                    best_path_ip = ipv6_show_bgp_json["routes"][network["ipv6"]][index][
                        "nexthops"
                    ][i_index]["ip"]
                    output_dict["ipv6"] = best_path_ip
                    logger.info(
                        "[DUT [{}]] Best path for the route {} is  {} ".format(
                            dut, network["ipv6"], best_path_ip
                        )
                    )

        else:
            logger.error("ERROR....! No Best Path  Found in BGP RIB.... FAILED")
    if is_ipv4_best_path_found:
        return output_dict
    else:
        logger.error("ERROR...! Unable to find the Best Path in the RIB")
        return False


#####################################################
#
#                      Testcases
#
#####################################################


def test_verify_bgp_default_originate_with_default_static_route_p1(request):
    """
    Summary: "Verify default-originate route with default static and network command  "

    """
    tgen = get_topogen()
    global BGP_CONVERGENCE, DEFAULT_ROUTE_NXT_HOP_LINK1, DEFAULT_ROUTE_NXT_HOP_LINK2, DEFAULT_ROUTES

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Configure 2 link between R1 and R2")
    step("Configure IPV4 and IPV6 EBGP between R1 and R2  both the links")
    step("Configure default-originate on R1 IPv4 and IPv6 BGP session link-1 only ")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {"r2": {"dest-link": "r1-link1"}}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {"r2": {"dest-link": "r1-link1"}}
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify IPv4/IPv6 default originate routes present on R2 nexthop as link-1")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r2": {
                "static_routes": [
                    {
                        "network": [DEFAULT_ROUTES[addr_type]],
                        "next_hop": DEFAULT_ROUTE_NXT_HOP_LINK1[addr_type],
                    }
                ]
            }
        }

        result = verify_fib_routes(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_LINK1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            static_routes_input,
            next_hop=DEFAULT_ROUTE_NXT_HOP_LINK1[addr_type],
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure  network command on R1 (0.0.0.0/0 and 0::0/0) for IPv4 and IPv6 address family "
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": [DEFAULT_ROUTES[addr_type]]}
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_advertise)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("No change on IPv4/IPv6  default-originate route advertised from link1")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify 0.0.0.0/0 and 0::0/0 route also get advertised from link-2  ")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Before removing default originate from R1 link -1 IPv4 and IPv6 address family taking the uptime snapshot"
    )
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("Remove default originate from R1 link -1 IPv4 and IPv6 address family ")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Routes must be learned from network command")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("After removing the default originate  on R1 taking the uptime snapshot")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After removing the default-originate uptime should get reset for link-1 learn route"
    )
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot before configuring default - originate")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)
    sleep(1)

    step(
        "Configure default-originate on R1 link-1 again for IPv4 and IPv6 address family"
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify No change on R2 routing and BGP table for both the links ")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking snapshot after configuring default - originate")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After configuring the default-originate uptime should not get reset for link-1 learn route"
    )
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=True)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=True)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot before  removing  network 0.0.0.0  ")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("Remove network command from R1 IPv4/IPv6 address family ")
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [DEFAULT_ROUTES[addr_type]],
                                        "delete": True,
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_advertise)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify 0.0.0.0/0 and 0::0/0 route get removed from link-2  and default-originate IPv4/IPv6 route learn on link-1"
    )
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Route from link2 is not expected \n Error: {}".format(
        tc_name, result
    )
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed\n Route from link2 is not expected \n  Error: {}".format(
        tc_name, result
    )

    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After removing default originate command on R1 verify that the uptime got reset on R2"
    )

    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot before  configuring static route  network")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "Configure static default route for IPv4 and IPv6 (0.0.0.0/0 next-hop Null0 and 0::0/0 next-hop Null0) on R1"
    )
    static_routes_input = {
        "r1": {
            "static_routes": [
                {
                    "network": "0.0.0.0/0",
                    "next_hop": NEXT_HOP_IP["ipv4"],
                },
                {
                    "network": "0::0/0",
                    "next_hop": NEXT_HOP_IP["ipv6"],
                },
            ]
        }
    }
    result = create_static_routes(tgen, static_routes_input)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verifyIPv4 and IPv6 static routes are configure and up on R1 ")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {
                        "network": "0.0.0.0/0",
                        "next_hop": NEXT_HOP_IP["ipv4"],
                    },
                    {
                        "network": "0::0/0",
                        "next_hop": NEXT_HOP_IP["ipv6"],
                    },
                ]
            }
        }
        result = verify_fib_routes(tgen, addr_type, "r1", static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure redistribute static on IPv4 and IPv6 address family")
    redistribute_static = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, redistribute_static)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify No change on IPv4/IPv6  default-originate route advertised from link1")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify 0.0.0.0/0 and 0::0/0 route also get advertised from link-2 ")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed\n Best Path sould be advertised in routes\n Error: {}".format(
        tc_name, result
    )

    step("Taking uptime snapshot before  removing  default originate")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("Remove default-originate from link-1 from IPv4 and IPv6 neighbor ")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Taking uptime snapshot after  removing  default originate")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("verify the up time , up time should get reset ")
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify No change on IPv4/IPv6  default-originate route advertised from link1")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot before  configuring  default originate")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        " Configure default-originate on link-1 again for IPv4 and IPv6 address family"
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify No change on IPv4/IPv6  default-originate route advertised from link1")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot after  configuring  default originate")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("After configuring the default originate the uptime should not get reset ")
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot before removing redistribute static")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)
    sleep(1)

    step("Remove redistribute static from IPv4 and IPv6 address family ")
    input_dict_1 = {
        "r1": {
            "bgp": {
                "local_as": get_dut_as_number(tgen, dut="r1"),
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
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify No change on IPv4/IPv6  default-originate route advertised from link1")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Now look that the route is not pointed at link2")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Taking uptime snapshot after removing redistribute static")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("After removing default originate the route uptime should get reset ")
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=True)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=True)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


def test_verify_bgp_default_originate_with_aggregate_summary_p1(request):
    """
    Summary: "Verify default-originate route with aggregate summary command"
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)
    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    step("After changing the BGP AS Path Verify the BGP Convergence")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Configure default-originate on R1 IPv4 and IPv6 BGP session link-1 only")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {"r2": {"dest-link": "r1-link1"}}
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {"r2": {"dest-link": "r1-link1"}}
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify IPv4/IPv6 default originate routes present on R2 nexthop as link-1,on R2"
    )
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure 5 static  route for IPv4 and IPv6  on R0")
    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [NETWORK1_1[addr_type]],
                                        "next_hop": NEXT_HOP_IP[addr_type],
                                    },
                                    {
                                        "network": [NETWORK1_2[addr_type]],
                                        "next_hop": NEXT_HOP_IP[addr_type],
                                    },
                                    {
                                        "network": [NETWORK1_3[addr_type]],
                                        "next_hop": NEXT_HOP_IP[addr_type],
                                    },
                                    {
                                        "network": [NETWORK1_4[addr_type]],
                                        "next_hop": NEXT_HOP_IP[addr_type],
                                    },
                                    {
                                        "network": [NETWORK1_5[addr_type]],
                                        "next_hop": NEXT_HOP_IP[addr_type],
                                    },
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_advertise)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Before configuring the aggregate route taking uptime snapshot  ")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("Configure aggregate summary command  for IPv4 and IPv6 address family ")
    local_as = get_dut_as_number(tgen, dut="r1")
    raw_config = {
        "r1": {
            "raw_config": [
                "router bgp {}".format(local_as),
                "address-family ipv4 unicast",
                "aggregate-address {} summary-only".format("0.0.0.0/0 "),
                "exit-address-family",
                "address-family ipv6 unicast",
                "aggregate-address {} summary-only".format("0::0/0"),
                "exit-address-family",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "verify that no change on IPv4/IPv6  default-originate route advertised from link1  0.0.0.0/0 and 0::0/0 route also get advertised from link-2    on R2"
    )
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("After configuring the aggregate route taking uptime snapshot  ")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After Configuring  the aggregate route uptime should get reset for link-1 learn route"
    )
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Before removing default originate  taking uptime snapshot ")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("Remove default originate from R1 link -1 IPv4 and IPv6 address family")
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {"dest-link": "r1-link1", "delete": True}
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "verify that no change on IPv4/IPv6  default-originate route advertised from link1  0.0.0.0/0 and 0::0/0 route also get advertised from link-2    on R2"
    )
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("After removing default origin taking uptime snapshot  ")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After removing the default-originate uptime should get reset for link-1 learn route"
    )
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Before Configuring default origin taking uptime snapshot ")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "Configure default-originate on R1 link-1 again for IPv4 and IPv6 address family"
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    default_originate_config = {
        "r1": {
            "bgp": {
                "local_as": local_as,
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "default_originate": {
                                "r2": {
                                    "dest-link": "r1-link1",
                                }
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, default_originate_config)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("After Configuring  default originate  taking uptime snapshot")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step(
        "After Configuring  the default-originate uptime should get reset for link-1 learn route"
    )
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Before removing aggregate -summary command taking the uptime snapshot ")
    uptime_before_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_before_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("remove aggregate summary command  for IPv4 and IPv6 address family ")
    local_as = get_dut_as_number(tgen, dut="r1")
    raw_config = {
        "r1": {
            "raw_config": [
                "router bgp {}".format(local_as),
                "address-family ipv4 unicast",
                "no aggregate-address {} summary-only".format("0.0.0.0/0"),
                "exit-address-family",
                "address-family ipv6 unicast",
                "no aggregate-address {} summary-only".format("0::0/0"),
                "exit-address-family",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify Default-originate IPv4/IPv6 route learn on link-1 ")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK1,
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify 0.0.0.0/0 and 0::0/0 route get removed from link-2 ")
    result = verify_rib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = verify_fib_default_route(
        tgen,
        topo,
        dut="r2",
        routes=DEFAULT_ROUTES,
        expected_nexthop=DEFAULT_ROUTE_NXT_HOP_LINK2,
        expected=False,
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("After removing aggregate -summary command taking the uptime snapshot ")
    uptime_after_ipv4 = get_rib_route_uptime(tgen, "ipv4", "r2", ipv4_uptime_dict)
    uptime_after_ipv6 = get_rib_route_uptime(tgen, "ipv6", "r2", ipv6_uptime_dict)

    step("After removing aggregate command uptime should get reset ")
    result = verify_the_uptime(uptime_before_ipv4, uptime_after_ipv4, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_the_uptime(uptime_before_ipv6, uptime_after_ipv6, incremented=False)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    write_test_footer(tc_name)


def test_verify_default_originate_with_2way_ecmp_p2(request):
    """
    Summary: "Verify default-originate route with 3 way ECMP and traffic "
    """

    tgen = get_topogen()
    global BGP_CONVERGENCE
    global DEFAULT_ROUTES
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Populating next-hops details")
    r1_r2_ipv4_neighbor_ips = []
    r1_r2_ipv6_neighbor_ips = []
    r1_link = None
    for index in range(1, 3):
        r1_link = "r1-link" + str(index)
        r1_r2_ipv4_neighbor_ips.append(
            topo["routers"]["r2"]["links"][r1_link]["ipv4"].split("/")[0]
        )
        r1_r2_ipv6_neighbor_ips.append(
            topo["routers"]["r2"]["links"][r1_link]["ipv6"].split("/")[0]
        )

    step(
        "Configure default-originate on R1 for all the neighbor of IPv4 and IPv6 peers "
    )
    local_as = get_dut_as_number(tgen, dut="r1")
    for index in range(2):
        raw_config = {
            "r1": {
                "raw_config": [
                    "router bgp {}".format(local_as),
                    "address-family ipv4 unicast",
                    "neighbor {} default-originate".format(
                        r1_r2_ipv4_neighbor_ips[index]
                    ),
                    "exit-address-family",
                    "address-family ipv6 unicast",
                    "neighbor {} default-originate ".format(
                        r1_r2_ipv6_neighbor_ips[index]
                    ),
                    "exit-address-family",
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After configuring default-originate command , verify default  routes are advertised on R2 "
    )

    r2_link = None
    for index in range(1, 3):
        r2_link = "r2-link" + str(index)
        ipv4_nxt_hop = topo["routers"]["r1"]["links"][r2_link]["ipv4"].split("/")[0]
        interface = topo["routers"]["r1"]["links"][r2_link]["interface"]
        ipv6_link_local_nxt_hop = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
        DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local_nxt_hop}

        result = verify_rib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Ping R1 configure IPv4 and IPv6 loopback address from R2")
    pingaddr = topo["routers"]["r1"]["links"]["lo"]["ipv4"].split("/")[0]
    router = tgen.gears["r2"]

    def ping_router():
        output = router.run("ping -c 4 -w 4 {}".format(pingaddr))
        logger.info(output)
        if " 0% packet loss" not in output:
            return False

    _, res = topotest.run_and_expect(ping_router, None, count=10, wait=1)
    logger.info("Ping from R1 to R2 ... success")

    step("Shuting up the active route")
    network = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
    ipv_dict = get_best_path_route_in_FIB(tgen, topo, dut="r2", network=network)
    dut_links = topo["routers"]["r1"]["links"]
    active_interface = None
    for key, _ in dut_links.items():
        ipv4_address = dut_links[key]["ipv4"].split("/")[0]
        ipv6_address = dut_links[key]["ipv6"].split("/")[0]
        if ipv_dict["ipv4"] == ipv4_address and ipv_dict["ipv6"] == ipv6_address:
            active_interface = dut_links[key]["interface"]

    logger.info(
        "Shutting down the interface {} on router {} ".format(active_interface, "r1")
    )
    shutdown_bringup_interface(tgen, "r1", active_interface, False)

    step("Verify the complete convergence  to fail after  shutting  the interface")
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        result is not True
    ), " Testcase {} : After shuting down the interface  Convergence is expected to be Failed".format(
        tc_name
    )

    step(
        "Verify  routes from active best path is not received from  r1 after  shuting the interface"
    )
    r2_link = None
    for index in range(1, 3):
        r2_link = "r2-link" + str(index)
        ipv4_nxt_hop = topo["routers"]["r1"]["links"][r2_link]["ipv4"].split("/")[0]
        interface = topo["routers"]["r1"]["links"][r2_link]["interface"]
        ipv6_link_local_nxt_hop = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
        DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local_nxt_hop}
        if index == 1:
            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
                expected=False,
            )
            assert result is not True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        else:
            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Ping R1 configure IPv4 and IPv6 loopback address from R2")
    pingaddr = topo["routers"]["r1"]["links"]["lo"]["ipv4"].split("/")[0]
    router = tgen.gears["r2"]
    output = router.run("ping -c 4 -w 4 {}".format(pingaddr))
    assert " 0% packet loss" in output, "Ping R1->R2  FAILED"
    logger.info("Ping from R1 to R2 ... success")

    step("No Shuting up the active route")

    shutdown_bringup_interface(tgen, "r1", active_interface, True)

    step("Verify the complete convergence after bringup the interface")
    result = verify_bgp_convergence(tgen, topo)
    assert (
        result is True
    ), " Testcase {} : After bringing up  the interface  complete convergence is expected ".format(
        tc_name
    )

    step("Verify all the routes are received from  r1 after no shuting the interface")
    r2_link = None
    for index in range(1, 3):
        r2_link = "r2-link" + str(index)
        ipv4_nxt_hop = topo["routers"]["r1"]["links"][r2_link]["ipv4"].split("/")[0]
        interface = topo["routers"]["r1"]["links"][r2_link]["interface"]
        ipv6_link_local_nxt_hop = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
        DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local_nxt_hop}
        if index == 1:
            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )
        else:
            result = verify_rib_default_route(
                tgen,
                topo,
                dut="r2",
                routes=DEFAULT_ROUTES,
                expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Configure IPv4 and IPv6  route-map with deny option on R2 to filter default route  0.0.0.0/0 and 0::0/0"
    )
    DEFAULT_ROUTES = {"ipv4": "0.0.0.0/0", "ipv6": "0::0/0"}
    input_dict_3 = {
        "r2": {
            "prefix_lists": {
                "ipv4": {
                    "Pv4": [
                        {
                            "seqid": "1",
                            "network": DEFAULT_ROUTES["ipv4"],
                            "action": "permit",
                        }
                    ]
                },
                "ipv6": {
                    "Pv6": [
                        {
                            "seqid": "1",
                            "network": DEFAULT_ROUTES["ipv6"],
                            "action": "permit",
                        }
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMv4": [
                    {
                        "action": "deny",
                        "seq_id": "1",
                        "match": {"ipv4": {"prefix_lists": "Pv4"}},
                    },
                ],
                "RMv6": [
                    {
                        "action": "deny",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "Pv6"}},
                    },
                ],
            }
        }
    }
    result = create_route_maps(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Apply route-map IN direction of R2 ( R2-R1) for IPv4 and IPv6 BGP neighbors")
    r2_link = None
    for index in range(1, 3):
        r2_link = "r2-link" + str(index)
        input_dict_4 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            r2_link: {
                                                "route_maps": [
                                                    {"name": "RMv4", "direction": "in"}
                                                ]
                                            },
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            r2_link: {
                                                "route_maps": [
                                                    {"name": "RMv6", "direction": "in"}
                                                ]
                                            },
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("After applying the route-map the routes are not expected in RIB ")
    r2_link = None
    for index in range(1, 3):
        r2_link = "r2-link" + str(index)
        ipv4_nxt_hop = topo["routers"]["r1"]["links"][r2_link]["ipv4"].split("/")[0]
        interface = topo["routers"]["r1"]["links"][r2_link]["interface"]
        ipv6_link_local_nxt_hop = get_frr_ipv6_linklocal(tgen, "r1", intf=interface)
        DEFAULT_ROUTE_NXT_HOP = {"ipv4": ipv4_nxt_hop, "ipv6": ipv6_link_local_nxt_hop}

        result = verify_rib_default_route(
            tgen,
            topo,
            dut="r2",
            routes=DEFAULT_ROUTES,
            expected_nexthop=DEFAULT_ROUTE_NXT_HOP,
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
