#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#


"""OSPF Summarisation Functionality Automation."""
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
from time import sleep

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    verify_ospf_rib,
    create_router_ospf,
    verify_ospf_summary,
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
    ]
}
NETWORK2 = {
    "ipv4": [
        "12.0.20.1/32",
        "12.0.20.2/32",
        "12.0.20.3/32",
        "12.0.20.4/32",
        "12.0.20.5/32",
    ]
}
NETWORK3 = {
    "ipv4": [
        "13.0.20.1/32",
        "13.0.20.2/32",
        "13.0.20.3/32",
        "13.0.20.4/32",
        "13.0.20.5/32",
    ]
}
SUMMARY = {"ipv4": ["11.0.20.1/8", "12.0.0.0/8", "13.0.0.0/8", "11.0.0.0/8"]}
"""
TOPOOLOGY =
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



TESTCASES =
1. OSPF summarisation with type7 LSAs.

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
    json_file = "{}/ospf_asbr_summary_type7_lsa.json".format(CWD)
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
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error  {}".format(
        ospf_covergence
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

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def red_static(dut, config=True):
    """Local def for Redstribute static routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    else:
        ospf_red = {
            dut: {"ospf": {"redistribute": [{"redist_type": "static", "delete": True}]}}
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)


def red_connected(dut, config=True):
    """Local def for Redstribute connected routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": "connected"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf": {
                    "redistribute": [{"redist_type": "connected", "del_action": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospf_type5_summary_tc44_p0(request):
    """OSPF summarisation with type7 LSAs"""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Bring up the base config as per the topology")
    step("Configure area 1 as NSSA Area")

    reset_config_on_routers(tgen)

    dut = "r0"
    protocol = "ospf"

    red_static(dut)
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv4"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv4"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv4", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")

    ospf_summ_r0 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "8"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )

    step("Configure summary & redistribute static/connected route with  metric type 2")

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv4"][3]}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv4"][3]: {
            "summaryAddress": SUMMARY["ipv4"][3],
            "metricType": "E2",
            "metric": 20,
            "tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Summary missing in OSPF DB".format(tc_name)

    step("Learn type 7 lsa from neighbours")

    dut = "r1"
    protocol = "ospf"

    red_static(dut)
    input_dict_static_rtes = {
        "r1": {
            "static_routes": [{"network": NETWORK3["ipv4"], "next_hop": "blackhole"}]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that routes are learnt on R0.")
    dut = "r0"

    result = verify_ospf_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv4", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Routes is missing in RIB".format(tc_name)

    ospf_summ_r0 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][2].split("/")[0], "mask": "8"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that type7 LSAs received from neighbor are not summarised.")
    input_dict = {
        "13.0.0.0/8": {
            "summaryAddress": "13.0.0.0/8",
            "metricType": "E2",
            "metric": 20,
            "tag": 0,
            "externalRouteCount": 0,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that already originated summary is intact.")
    input_dict = {
        SUMMARY["ipv4"][3]: {
            "summaryAddress": SUMMARY["ipv4"][3],
            "metricType": "E2",
            "metric": 20,
            "tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed. Error: Summary missing in OSPF DB".format(tc_name)

    dut = "r1"
    aggr_timer = {"r1": {"ospf": {"aggr_timer": 6}}}
    result = create_router_ospf(tgen, topo, aggr_timer)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    ospf_summ_r0 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][2].split("/")[0], "mask": "8"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "wait for 6+1 seconds as ospf aggregation start after 6 secs as "
        "per the above aggr_timer command"
    )
    sleep(7)
    dut = "r1"
    aggr_timer = {"r1": {"ospf": {"del_aggr_timer": 6}}}
    result = create_router_ospf(tgen, topo, aggr_timer)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
