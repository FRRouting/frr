#!/usr/bin/python
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


"""OSPF Basic Functionality Automation."""
import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
import ipaddress

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    shutdown_bringup_interface,
    create_interfaces_cfg,
    topo_daemons,
    get_frr_ipv6_linklocal,
)

from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf6_neighbor,
    verify_ospf6_rib,
    create_router_ospf,
    verify_ospf6_interface,
    config_ospf6_interface,
)


pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]


# Global variables
topo = None

NETWORK = {
    "ipv6": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ],
    "ipv6": ["2::1/128", "2::2/128", "2::3/128", "2::4/128", "2::5/128"],
}
TOPOOLOGY = """
      Please view in a fixed-width font such as Courier.
      +---+  A1       +---+
      +R1 +------------+R2 |
      +-+-+-           +--++
        |  --        --  |
        |    -- A0 --    |
      A0|      ----      |
        |      ----      | A2
        |    --    --    |
        |  --        --  |
      +-+-+-            +-+-+
      +R0 +-------------+R3 |
      +---+     A3     +---+
"""

TESTCASES = """
1. OSPF Cost - verifying ospf interface cost functionality
"""


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
    json_file = "{}/ospfv3_rte_calc.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, topo)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen, daemons)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
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


def red_static(dut, config=True):
    """Local def for Redstribute static routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf6": {"redistribute": [{"redist_type": "static"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf6": {
                    "redistribute": [{"redist_type": "static", "del_action": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)


def red_connected(dut, config=True):
    """Local def for Redstribute connected routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf6": {"redistribute": [{"redist_type": "connected"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf6": {
                    "redistribute": [{"redist_type": "connected", "del_action": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################
def test_ospfv3_redistribution_tc5_p0(request):
    """Test OSPF intra area route calculations."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step("Verify that OSPF neighbors are FULL.")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("verify intra area route is calculated for r0-r3 interface ip in R1")
    ip = topo["routers"]["r0"]["links"]["r3"]["ipv6"]
    ip_net = str(ipaddress.ip_interface(u"{}".format(ip)).network)

    llip = get_llip("r0", "r1")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)

    nh = llip
    input_dict = {
        "r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N"}]}
    }

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address on newly configured loopback of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo["routers"]["r0"]["links"]["r3"]["ipv6"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Route present in RIB. Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Route present in RIB. Error: {}".format(tc_name, result)

    step("Add back the deleted ip address on newly configured interface of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo["routers"]["r0"]["links"]["r3"]["ipv6"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut no shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("un shut the OSPF interface on R0")
    dut = "r0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_redistribution_tc6_p0(request):
    """Test OSPF inter area route calculations."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step("Verify that OSPF neighbors are FULL.")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("verify intra area route is calculated for r0-r3 interface ip in R1")
    ip = topo["routers"]["r0"]["links"]["r3"]["ipv6"]
    ip_net = str(ipaddress.ip_interface(u"{}".format(ip)).network)
    llip = get_llip("r0", "r1")
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, llip)
    nh = llip
    input_dict = {
        "r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N"}]}
    }

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address on newly configured loopback of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo["routers"]["r0"]["links"]["r3"]["ipv6"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Route present in RIB. Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Route present in RIB. Error: {}".format(tc_name, result)

    step("Add back the deleted ip address on newly configured interface of R0")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo["routers"]["r0"]["links"]["r3"]["ipv6"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut no shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("Verify that intraroute calculated for R1 intf on R0 is deleted.")
    dut = "r1"

    step("un shut the OSPF interface on R0")
    dut = "r0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_cost_tc52_p0(request):
    """OSPF Cost - verifying ospf interface cost functionality"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    step(
        "Configure ospf cost as 20 on interface between R0 and R1. "
        "Configure ospf cost as 30 between interface between R0 and R2."
    )

    r0_ospf_cost = {
        "r0": {"links": {"r1": {"ospf6": {"cost": 20}}, "r2": {"ospf6": {"cost": 30}}}}
    }
    result = config_ospf6_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between"
        " r0 and r1 as 30 and r0 and r2 as 20"
    )
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=r0_ospf_cost)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Swap the costs between interfaces on r0, between r0 and r1 to 30"
        ", r0 and r2 to 20"
    )

    r0_ospf_cost = {
        "r0": {"links": {"r1": {"ospf6": {"cost": 30}}, "r2": {"ospf6": {"cost": 20}}}}
    }
    result = config_ospf6_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between r0 "
        "and r1 as 30 and r0 and r2 as 20."
    )
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=r0_ospf_cost)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure cost from the interface r0 - r1.")

    r0_ospf_cost = {
        "r0": {"links": {"r1": {"ospf6": {"cost": 30, "del_action": True}}}}
    }
    result = config_ospf6_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {"links": {"r1": {"ospf6": {"cost": 10}}, "r2": {"ospf6": {"cost": 20}}}}
    }
    step(
        "Verify that cost is updated in the ospf interface between r0"
        " and r1 as 10 and r0 and r2 as 20."
    )

    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Un configure cost from the interface r0 - r2.")

    r0_ospf_cost = {
        "r0": {"links": {"r2": {"ospf6": {"cost": 20, "del_action": True}}}}
    }
    result = config_ospf6_interface(tgen, topo, r0_ospf_cost)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that cost is updated in the ospf interface between r0"
        "and r1 as 10 and r0 and r2 as 10"
    )

    input_dict = {
        "r0": {"links": {"r1": {"ospf6": {"cost": 10}}, "r2": {"ospf6": {"cost": 10}}}}
    }
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
