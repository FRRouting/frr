#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
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

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
    get_frr_ipv6_linklocal,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf6_neighbor,
    clear_ospf,
    verify_ospf6_rib,
    create_router_ospf,
)


pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]


# Global variables
topo = None

NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ],
    "ipv6": ["2::1/128", "2::2/128", "2::3/128", "2::4/128", "2::5/128"],
}
MASK = {"ipv6": "32", "ipv6": "128"}

"""
TOPOOLOGY =
      Please view in a fixed-width font such as Courier.
      Topo : Broadcast Networks
        +---+       +---+          +---+           +---+
        |R0 +       +R1 +          +R2 +           +R3 |
        +-+-+       +-+-+          +-+-+           +-+-+
          |           |              |               |
          |           |              |               |
        --+-----------+--------------+---------------+-----
                         Ethernet Segment

TESTCASES =
1.  Verify OSPF ECMP with max path configured as 8
    (Edge having 1 uplink port as broadcast network,
    connect to 8 TORs - LAN case)

 """


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, switch_name
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ospfv3_ecmp_lan.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert ospf_covergence is True, "setup_module :Failed \n Error:  {}".format(
        ospf_covergence
    )

    switch_name = [k for k in topo["switches"].keys()][0]

    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment.

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files

    try:
        # Stop toplogy and Remove tmp files
        tgen.stop_topology()

    except OSError:
        # OSError exception is raised when mininet tries to stop switch
        # though switch is stopped once but mininet tries to stop same
        # switch again, where it ended up with exception
        pass
    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def red_static(dut, config=True):
    """Local def for Redstribute static routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf6": {"redistribute": [{"redist_type": "static"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf6": {"redistribute": [{"redist_type": "static", "delete": True}]}
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


def test_ospfv3_lan_ecmp_tc18_p0(request):
    """
    OSPF ECMP.

    Verify OSPF ECMP with max path configured as 8
    (Edge having 1 uplink port as broadcast network,
    connect to 8 TORs - LAN case)

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step(". Configure ospf in all the routers on LAN interface.")

    reset_config_on_routers(tgen)

    step("Verify that OSPF is up with 8 neighborship sessions.")

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step(
        "Configure a static route in all the routes and "
        "redistribute static/connected in OSPF."
    )

    for rtr in topo["routers"]:
        input_dict = {
            rtr: {
                "static_routes": [
                    {"network": NETWORK["ipv6"][0], "no_of_ip": 5, "next_hop": "Null0"}
                ]
            }
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        dut = rtr
        red_static(dut)

    step(
        "Verify that route in R0 in stalled with 8 hops. "
        "Verify ospf route table and ip route table."
    )

    nh = []
    for rtr in topo["routers"]:
        llip = get_llip(rtr, switch_name)
        assert llip is not None, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        nh.append(llip)

    llip = get_llip("r1", switch_name)
    assert llip is not None, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    nh.remove(llip)
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf6"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" clear ip ospf interface on DUT(r0)")
    clear_ospf(tgen, "r0", ospf="ospf6")

    step(
        "Verify that after clearing the ospf interface all the "
        "neighbours are up and routes are installed with 8 next hop "
        "in ospf and ip route tables on R0"
    )

    dut = "r0"
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, lan=True)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step(" clear ip ospf interface on R2")
    clear_ospf(tgen, "r2")

    dut = "r2"
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, lan=True)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step("Delete static/connected cmd in ospf in all the routes one by one.")
    for rtr in topo["routers"]:
        input_dict = {
            rtr: {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "no_of_ip": 5,
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

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
