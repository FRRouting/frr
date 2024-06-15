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

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    scapy_send_raw_packet,
)

from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf_neighbor,
    verify_ospf_gr_helper,
    create_router_ospf,
)

pytestmark = [pytest.mark.ospfd]

# Global variables
topo = None
Iters = 5
sw_name = None
intf = None
intf1 = None
pkt = None

"""
Topology:

      Please view in a fixed-width font such as Courier.
      Topo : Broadcast Networks
      DUT - HR      RR
        +---+       +---+          +---+           +---+
        |R0 +       +R1 +          +R2 +           +R3 |
        +-+-+       +-+-+          +-+-+           +-+-+
          |           |              |               |
          |           |              |               |
        --+-----------+--------------+---------------+-----
                         Ethernet Segment

Testcases:

TC1.    Verify by default helper support is disabled for FRR ospf
TC2.    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
        sends grace lsa, helps RR to restart gracefully (RR = DR)
TC3.    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
        sends grace lsa, helps RR to restart gracefully (RR = BDR)
TC4.    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
        sends grace lsa, helps RR to restart gracefully (RR = DRother)
TC5.    OSPF GR on P2P : Verify DUT enters Helper mode when neighbor sends
        grace lsa, helps RR to restart gracefully.
TC6.    Verify all the show commands newly introducted as part of ospf
        helper support - Json Key verification wrt to show commands.
TC7.    Verify helper when grace lsa is received with different configured
        value in process level (higher, lower, grace lsa timer above 1800)
TC8.    Verify helper functionality when dut is helping RR and new grace lsa
        is received from RR.
"""


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, intf, intf1, sw_name, pkt
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ospf_gr_helper.json".format(CWD)
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

    ospf_covergence = verify_ospf_neighbor(tgen, topo, lan=True)
    assert ospf_covergence is True, "setup_module :Failed \n Error:  {}".format(
        ospf_covergence
    )

    sw_name = "s1"
    intf = topo["routers"]["r0"]["links"][sw_name]["interface"]
    intf1 = topo["routers"]["r1"]["links"][sw_name]["interface"]
    pkt = topo["routers"]["r1"]["opq_lsa_hex"]

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    try:
        # Stop toplogy and Remove tmp files
        tgen.stop_topology()

    except OSError:
        # OSError exception is raised when mininet tries to stop switch
        # though switch is stopped once but mininet tries to stop same
        # switch again, where it ended up with exception
        pass


def delete_ospf():
    """delete ospf process after each test"""
    tgen = get_topogen()
    step("Delete ospf process")
    for rtr in topo["routers"]:
        ospf_del = {rtr: {"ospf": {"delete": True}}}
        result = create_router_ospf(tgen, topo, ospf_del)
        assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospf_gr_helper_tc1_p0(request):
    """Verify by default helper support is disabled for FRR ospf"""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)
    ospf_covergence = verify_ospf_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:  {}".format(ospf_covergence)

    step("Verify that GR helper route is disabled by default to the in the DUT.")
    input_dict = {
        "helperSupport": "Disabled",
        "strictLsaCheck": "Enabled",
        "restartSupport": "Planned and Unplanned Restarts",
        "supportedGracePeriod": 1800,
    }
    dut = "r0"
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT does not enter helper mode upon receiving the  grace lsa.")

    # send grace lsa
    scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)

    input_dict = {"activeRestarterCnt": 1}
    dut = "r0"
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed. DUT entered helper role   \n Error: {}".format(
        tc_name, result
    )

    step("Configure graceful restart in the DUT")
    ospf_gr_r0 = {
        "r0": {"ospf": {"graceful-restart": {"helper enable": [], "opaque": True}}}
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that GR helper route is enabled in the DUT.")
    input_dict = {
        "helperSupport": "Enabled",
        "strictLsaCheck": "Enabled",
        "restartSupport": "Planned and Unplanned Restarts",
        "supportedGracePeriod": 1800,
    }
    dut = "r0"
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {"ospf": {"graceful-restart": {"helper enable": [], "opaque": True}}}
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR in RR.")
    step("Verify that DUT does enter helper mode upon receiving  the grace lsa.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Unconfigure the GR helper command.")
    ospf_gr_r0 = {
        "r0": {
            "ospf": {
                "graceful-restart": {
                    "helper enable": [],
                    "opaque": True,
                    "delete": True,
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"helperSupport": "Disabled"}
    dut = "r0"
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure gr helper using the router id")
    ospf_gr_r0 = {
        "r0": {
            "ospf": {"graceful-restart": {"helper enable": ["1.1.1.1"], "opaque": True}}
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT does enter helper mode upon receiving  the grace lsa.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Un Configure gr helper using the router id")
    ospf_gr_r0 = {
        "r0": {
            "ospf": {
                "graceful-restart": {
                    "helper enable": ["1.1.1.1"],
                    "opaque": True,
                    "delete": True,
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that GR helper router is disabled in the DUT for  router id x.x.x.x")
    input_dict = {"enabledRouterIds": [{"routerId": "1.1.1.1"}]}
    dut = "r0"
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed, Helper role enabled for RR\n Error: {}".format(
        tc_name, result
    )
    delete_ospf()
    write_test_footer(tc_name)


def test_ospf_gr_helper_tc2_p0(request):
    """
    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
    sends grace lsa, helps RR to restart gracefully (RR = DR)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )
    reset_config_on_routers(tgen)
    ospf_covergence = verify_ospf_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:  {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {"ospf": {"graceful-restart": {"helper enable": [], "opaque": True}}}
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {"ospf": {"graceful-restart": {"helper enable": [], "opaque": True}}}
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
