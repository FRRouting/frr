#!/usr/bin/env python

#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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

"""
TC1. Verify bgp next hop modification using next hop self command.
TC2. Verify bgp next hop modification using set next hop command in route map.
TC3. Verify bgp next hop modification using set next hop command in route map and next hop self in bgp.
"""

import os
import sys
import time
import pytest


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    verify_rib,
    step,
    check_router_status,
    get_frr_ipv6_linklocal,
    start_topology,
    write_test_header,
    step,
    write_test_footer,
    verify_rib,
    check_address_types,
    reset_config_on_routers,
    check_router_status,
    stop_router,
    kill_router_daemons,
    start_router,
    shutdown_bringup_interface,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    clear_bgp_and_verify,
    verify_bgp_rib,
    clear_bgp_and_verify,
)
from lib.topojson import build_config_from_json

# Global variables
topo = None

# Global variables
NETWORK = {
    "ipv4": ["192.0.2.1/32", "192.0.2.2/32"],
    "ipv6": ["192::0:2:1/128", "192::0:2:2/128"],
}
MASK = {"ipv4": "32", "ipv6": "128"}
NEXT_HOP = {
    "ipv4": ["10.0.0.1", "10.0.0.5", "10.0.0.9"],
    "ipv6": ["Null0", "Null0", "Null0", "Null0", "Null0"],
}
NO_OF_RTES = 2
NETWORK_CMD_IP = "1.0.1.17/32"
ADDR_TYPES = check_address_types()
BGP_CONVERGENCE_TIMEOUT = 10




def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_nh_modification.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

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


def get_nh(onrouter, intf, addr_type="ipv4", llip=False):
    """
    API to get the link local ipv6 address of a perticular interface

    Parameters
    ----------
    * `onrouter`: Source node
    * `intf` : interface for which link local ip needs to be returned.
    * `addr_type` : Address type of the address to be returned.
    * `llip` : True if link local ip is required, False if global ip is required.

    Usage
    -----
    result = get_nh(onrouter, intf, addr_type="ipv4", llip=False)

    Returns
    -------
    0) global ipv4 address from the interface.
    1) link local ipv6 address from the interface.
    2) errormsg - when link local ip not found.
    3) None - when global ip not found.
    """
    global topo
    tgen = get_topogen()
    if addr_type == "ipv4":
        return topo["routers"][onrouter]["links"][intf][addr_type].split("/")[0]
    elif addr_type == "ipv6" and llip is False:
        return topo["routers"][onrouter]["links"][intf][addr_type].split("/")[0]
    elif addr_type == "ipv6" and llip is True:
        intf = topo["routers"][onrouter]["links"][intf]["interface"]
        llip = get_frr_ipv6_linklocal(tgen, onrouter, intf)
        if llip:
            logger.info("llip ipv6 address to be set as NH is %s", llip)
            return llip.split("/")[0]
    return None


#####################################################
#
#   Testcases
#
#####################################################


def test_bgp_nh_modification_tc1_p0(request):
    """  Verify bgp next hop modification using next hop self command. """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step("Verify routes redistributed on R1 bgp are installed in R2 RIB.")

    dut = "r2"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r1", "r2", addr_type, llip=True)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure bgp nbr with the next hop self command in ibgp on DUT.")

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r2": {"next_hop_self": True}}},
                                "r4": {"dest_link": {"r2": {"next_hop_self": True}}},
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r2": {"next_hop_self": True}}},
                                "r4": {"dest_link": {"r2": {"next_hop_self": True}}},
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Clear bgp on DUT.")
    dut = "r2"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the route are installed with next hop of DUT in the RT3 and RT4 bgp table."
    )

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Delete the routes from RT1.")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "no_of_ip": 2,
                        "next_hop": "Null0",
                        "delete": True,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, bgp_rib)
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_bgp_rtes,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, bgp_rib)
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_bgp_rtes,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    step("Re configure routes on RT1.")

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "no_of_ip": 2, "next_hop": "Null0"}
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that the route are installed with next hop of DUT  in the RT3 and RT4 bgp table."
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure static routes on RT1 with multiple next hops to the "
        "same destination and redistribute in RT1 bgp."
    )

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "no_of_ip": 2, "next_hop": "Null0"}
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that the routes are installed with next hop DUT interface ip address in RT3 and RT4 routing table."
    )

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Delete the static routes on on RT1 with multiple next hops to the same destination and redistribute in RT1 bgp."
    )
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "no_of_ip": 2,
                        "next_hop": "Null0",
                        "delete": True,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that routes are withdrawn by DUT on RT3 and RT4.")

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, bgp_rib)
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_bgp_rtes,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, bgp_rib)
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_bgp_rtes,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    write_test_footer(tc_name)


def test_bgp_nh_modification_chaos_tc7_p2(request):
    """  Chaos - Verify bgp next hop modification functionality with chaos. """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Configure  next-hop-self in the bgp on DUT for the prefixes 10.x.x.x and "
        "  Configure next hop using route map for prefixes 11.x.x.x"
    )

    dut = "r2"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r1", "r2", addr_type, llip=True)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure bgp nbr with the next hop self command in ibgp on DUT.")

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r2": {"next_hop_self": True}}},
                                "r4": {"dest_link": {"r2": {"next_hop_self": True}}},
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r2": {"next_hop_self": True}}},
                                "r4": {"dest_link": {"r2": {"next_hop_self": True}}},
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart FRR router/Service on DUT.")
    dut = "r2"

    # restart bgpd router and verify
    stop_router(tgen, dut)
    start_router(tgen, dut)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the route are installed with next hop of DUT in the RT3 and RT4 bgp table."
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart bgpd on DUT.")
    dut = "r2"

    # restart bgpd router and verify
    kill_router_daemons(tgen, dut, ["bgpd"])

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the route are installed with next hop of DUT in the RT3 and RT4 bgp table."
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart zebrad on DUT.")
    dut = "r2"

    # restart bgpd router and verify
    kill_router_daemons(tgen, dut, ["zebra"])

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the route are installed with next hop of DUT in the RT3 and RT4 bgp table."
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart staticd on RT1.")
    dut = "r1"

    # restart bgpd router and verify
    kill_router_daemons(tgen, dut, ["staticd"])

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the route are installed with next hop of DUT in the RT3 and RT4 bgp table."
    )
    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Clear bgp in all the routers on DUT.")
    dut = "r2"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r4"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r4", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Shut no shut next hop interface")
    intf_r2_r3 = topo["routers"]["r2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r3, ifaceaction=False)

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, expected=False
        )
        assert bgp_rib is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, bgp_rib)
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_nh_for_bgp_rtes,
            next_hop=nh,
            protocol=protocol,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    step("Shut no shut next hop interface")
    intf_r2_r3 = topo["routers"]["r2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r3, ifaceaction=True)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    dut = "r3"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        nh = get_nh("r2", "r3", addr_type)
        verify_nh_for_bgp_rtes = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type][0], "no_of_ip": 2, "next_hop": nh}
                ]
            }
        }
        bgp_rib = verify_bgp_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh
        )
        assert bgp_rib is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, bgp_rib
        )
        result = verify_rib(
            tgen, addr_type, dut, verify_nh_for_bgp_rtes, next_hop=nh, protocol=protocol
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
