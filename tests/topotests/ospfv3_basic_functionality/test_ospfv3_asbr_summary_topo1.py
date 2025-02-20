#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
import ipaddress
from time import sleep

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    stop_router,
    start_router,
    verify_rib,
    create_static_routes,
    step,
    create_route_maps,
    shutdown_bringup_interface,
    create_prefix_lists,
    create_route_maps,
    create_interfaces_cfg,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf6_neighbor,
    clear_ospf,
    verify_ospf6_rib,
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
    ],
    "ipv6": [
        "2011:0:20::1/128",
        "2011:0:20::2/128",
        "2011:0:20::3/128",
        "2011:0:20::4/128",
        "2011:0:20::5/128",
    ],
}
NETWORK_11 = {
    "ipv4": ["11.0.20.6/32", "11.0.20.7/32"],
    "ipv6": ["2011:0:20::6/128", "2011:0:20::7/128"],
}

NETWORK2 = {
    "ipv4": [
        "12.0.20.1/32",
        "12.0.20.2/32",
        "12.0.20.3/32",
        "12.0.20.4/32",
        "12.0.20.5/32",
    ],
    "ipv6": [
        "2012:0:20::1/128",
        "2012:0:20::2/128",
        "2012:0:20::3/128",
        "2012:0:20::4/128",
        "2012:0:20::5/128",
    ],
}
SUMMARY = {
    "ipv4": ["11.0.0.0/8", "12.0.0.0/8", "11.0.0.0/24"],
    "ipv6": ["2011::/32", "2012::/32", "2011::/64", "2011::/24"],
}
"""
TOPOOLOGY =
      Please view in a fixed-width font such as Courier.
      +---+  A0       +---+
      +R1 +------------+R2 |
      +-+-+-           +--++
        |  --        --  |
        |    -- A0 --    |
      A0|      ----      |
        |      ----      | A0
        |    --    --    |
        |  --        --  |
      +-+-+-            +-+-+
      +R0 +-------------+R3 |
      +---+     A0     +---+

TESTCASES =
1. OSPF summarisation functionality.
2. OSPF summarisation with advertise and no advertise option
3. OSPF summarisation with route map modification of metric type.
4. OSPF CLI Show  verify ospf ASBR summary config and show commands behaviours.
5. OSPF summarisation Chaos.
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
    json_file = "{}/ospfv3_asbr_summary_topo1.json".format(CWD)
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
    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:  {}".format(
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
    """
    Local 'def' for Redstribute static routes inside ospf.

    Parameters
    ----------
    * `dut` : DUT on which configs have to be made.
    * `config` : True or False, True by default for configure, set False for
                 unconfiguration.
    """
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
    """
    Local 'def' for Redstribute connected routes inside ospf

    Parameters
    ----------
    * `dut` : DUT on which configs have to be made.
    * `config` : True or False, True by default for configure, set False for
                 unconfiguration.
    """
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf6": {"redistribute": [{"redist_type": "connected"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf6": {
                    "redistribute": [{"redist_type": "connected", "delete": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospfv3_type5_summary_tc42_p0(request):
    """OSPF summarisation functionality."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step(
        "Configure External Route summary in R0 to summarise 5"
        " routes to one route. with aggregate timer as 6 sec"
    )

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ],
                "aggr_timer": 6,
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there  peer.")
    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Delete the configured summary")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "del_aggr_timer": True,
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that summary lsa is withdrawn from R1 and deleted from R0.")
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary Route still present in RIB".format(tc_name)

    step("show ip ospf summary should not have any summary address.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary still present in DB".format(tc_name)

    dut = "r1"
    step("All 5 routes are advertised after deletion of configured summary.")

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("configure the summary again and delete static routes .")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    input_dict = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole", "delete": True}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    step("Verify that summary route is withdrawn from R1.")

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Add back static routes.")
    input_dict_static_rtes = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary"
        " address on R0 and only one route is sent to R1."
    )
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show configure summaries.")

    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Configure new static route which is matching configured summary.")
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [{"network": NETWORK_11["ipv6"], "next_hop": "blackhole"}]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # step("verify that summary lsa is not refreshed.")
    # show ip ospf database command is not working, waiting for DEV fix.

    step("Delete one of the static route.")
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK_11["ipv6"], "next_hop": "blackhole", "delete": True}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # step("verify that summary lsa is not refreshed.")
    # show ip ospf database command is not working, waiting for DEV fix.

    # step("Verify that deleted static route is removed from ospf LSDB.")
    # show ip ospf database command is not working, waiting for DEV fix.

    step(
        "Configure redistribute connected and configure ospf external"
        " summary address to summarise the connected routes."
    )

    dut = "r0"
    red_connected(dut)
    clear_ospf(tgen, dut, ospf="ospf6")

    ip = topo["routers"]["r0"]["links"]["r3"]["ipv6"]

    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [{"prefix": ip_net.split("/")[0], "mask": "8"}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured "
        "summary address on R0 and only one route is sent to R1."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "fd00::/64"}]}}
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Shut one of the interface")
    intf = topo["routers"]["r0"]["links"]["r3-link0"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    # step("verify that summary lsa is not refreshed.")
    # show ip ospf database command is not working, waiting for DEV fix.

    # step("Verify that deleted connected route is removed from ospf LSDB.")
    # show ip ospf database command is not working, waiting for DEV fix.

    step("Un do shut the interface")
    shutdown_bringup_interface(tgen, dut, intf, True)

    # step("verify that summary lsa is not refreshed.")
    # show ip ospf database command is not working, waiting for DEV fix.

    # step("Verify that deleted connected route is removed from ospf LSDB.")
    # show ip ospf database command is not working, waiting for DEV fix.

    step("Delete OSPF process.")
    ospf_del = {"r0": {"ospf6": {"delete": True}}}
    result = create_router_ospf(tgen, topo, ospf_del)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Reconfigure ospf process with summary")
    reset_config_on_routers(tgen)

    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)
    red_connected(dut)
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 and only one route is sent to R1."
    )

    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # step("verify that summary lsa is not refreshed.")
    # show ip ospf database command is not working, waiting for DEV fix.

    step("Delete the redistribute command in ospf.")
    dut = "r0"
    red_connected(dut, config=False)
    red_static(dut, config=False)

    step("Verify that summary route is withdrawn from the peer.")

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "metric": "1234",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_type5_summary_tc43_p0(request):
    """OSPF summarisation with metric type 2."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Change the summary address mask to lower match (ex - 16 to 8)")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "16"},
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "delete": True,
                    },
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    sleep(5)

    input_dict = {
        "2011::/16": {
            "summaryAddress": "2011::/16",
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "2011::0/16"}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Change the summary address mask to higher match (ex - 8 to 24)")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "2011::/32": {
            "summaryAddress": "2011::/32",
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 0,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )
    step("Configure 2 summary address with different mask of same network.")
    step(
        "Verify that external routes(static / connected) are summarised "
        "to configured summary address with highest match."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "2011::0/32"}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step(" Un configure one of the summary address.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    sleep(5)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "2011::0/16"}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "16"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes(static / connected) are summarised "
        "to configured summary address with highest match."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": "2011::0/16"}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    write_test_footer(tc_name)


def ospfv3_type5_summary_tc45_p0(request):
    """OSPF summarisation with Tag option"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure OSPF on all the routers of the topology.")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": "1234",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary"
        " address on R0 and only one route is sent to R1 with configured tag."
    )
    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "1234"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries with tag.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1234,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Delete the configured summary")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": "1234",
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that summary lsa is withdrawn from R1 and deleted from R0.")
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary Route still present in RIB".format(tc_name)

    step("show ip ospf summary should not have any summary address.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1234,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary still present in DB".format(tc_name)

    step("Configure Min tag value")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32", "tag": 1}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "1"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries with tag.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Configure Max Tag Value")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": 4294967295,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "4294967295"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step(
        "Verify that boundary values tags are used for summary route"
        " using show ip ospf route command."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 4294967295,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("configure new static route with different tag.")
    input_dict_static_rtes_11 = {
        "r0": {
            "static_routes": [
                {"network": NETWORK_11["ipv6"], "next_hop": "blackhole", "tag": "88888"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes_11)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("New tag has not been used by summary address.")

    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "88888"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(
        tgen, dut, input_dict_summary, tag="88888", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen,
        "ipv6",
        dut,
        input_dict_summary,
        protocol=protocol,
        tag="88888",
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step(
        "Verify that boundary values tags are used for summary route"
        " using show ip ospf route command."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 88888,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Delete the configured summary address")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": 4294967295,
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that 6 routes are advertised to neighbour with 5 routes"
        " without any tag, 1 route with tag."
    )

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that summary address is flushed from neighbor.")

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Configure summary first & then configure matching static route.")

    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole", "delete": True},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole", "delete": True},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Repeat steps 1 to 10 of summarisation in non Back bone area.")
    reset_config_on_routers(tgen)

    step("Change the area id on the interface on R0")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.0"},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.1"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Change the area id on the interface  ")
    input_dict = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf6": {"area": "0.0.0.0"},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf6": {"area": "0.0.0.1"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, ospf_covergence
    )

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": "1234",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary"
        " address on R0 and only one route is sent to R1 with configured tag."
    )
    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "1234"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries with tag.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1234,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the configured summary")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that summary lsa is withdrawn from R1 and deleted from R0.")
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary Route still present in RIB".format(tc_name)

    step("show ip ospf summary should not have any summary address.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1234,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary still present in DB".format(tc_name)

    step("Configure Min tag value")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32", "tag": 1}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "1"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries with tag.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Configure Max Tag Value")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": 4294967295,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "4294967295"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step(
        "Verify that boundary values tags are used for summary route"
        " using show ip ospf route command."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 4294967295,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("configure new static route with different tag.")
    input_dict_static_rtes_11 = {
        "r0": {
            "static_routes": [
                {"network": NETWORK_11["ipv6"], "next_hop": "blackhole", "tag": "88888"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes_11)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("New tag has not been used by summary address.")

    input_dict_summary = {
        "r0": {"static_routes": [{"network": SUMMARY["ipv6"][0], "tag": "88888"}]}
    }
    dut = "r1"

    result = verify_ospf6_rib(
        tgen, dut, input_dict_summary, tag="88888", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen,
        "ipv6",
        dut,
        input_dict_summary,
        protocol=protocol,
        tag="88888",
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step(
        "Verify that boundary values tags are used for summary route"
        " using show ip ospf route command."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 88888,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Delete the configured summary address")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": 4294967295,
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that 6 routes are advertised to neighbour with 5 routes"
        " without any tag, 1 route with tag."
    )

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that summary address is flushed from neighbor.")

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Configure summary first & then configure matching static route.")

    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole", "delete": True},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole", "delete": True},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_type5_summary_tc46_p0(request):
    """OSPF summarisation with advertise and no advertise option"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure OSPF on all the routers of the topology.")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step(
        "Configure External Route summary in R0 to summarise 5"
        " routes to one route with no advertise option."
    )
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "advertise": False,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary"
        " address on R0 and  summary route is not advertised to neighbor as"
        " no advertise is configured.."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the  configured summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Delete the configured summary")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Summary has 5 sec delay timer, sleep 5 secs...")
    sleep(5)

    step("Verify that summary lsa is withdrawn from R1 and deleted from R0.")
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary Route still present in RIB".format(tc_name)

    step("show ip ospf summary should not have any summary address.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 1234,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(
        tgen, topo, dut, input_dict, ospf="ospf6", expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Summary still present in DB".format(tc_name)

    step("Reconfigure summary with no advertise.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "advertise": False,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary"
        " address on R0 and  summary route is not advertised to neighbor as"
        " no advertise is configured.."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the  configured summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step(
        "Change summary address from no advertise to advertise "
        "(summary-address 10.0.0.0 255.255.0.0)"
    )

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "advertise": False,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there  peer.")
    output = tgen.gears["r0"].vtysh_cmd(
        "show ipv6 ospf6 database as-external json", isjson=True
    )

    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 ospf6 database as-external json", isjson=True
    )

    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes is present in RIB".format(tc_name)

    write_test_footer(tc_name)


def test_ospfv3_type5_summary_tc48_p0(request):
    """OSPF summarisation with route map modification of metric type."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there  peer.")
    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step(
        "Configure route map and & rule to permit configured summary address,"
        " redistribute static & connected routes with the route map."
    )
    step("Configure prefixlist to permit the static routes, add to route map.")
    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv6": {
                    "pf_list_1_ipv6": [
                        {"seqid": 10, "network": "any", "action": "permit"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "match": {"ipv6": {"prefix_lists": "pf_list_1_ipv6"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_red_r1 = {
        "r0": {
            "ospf6": {
                "redistribute": [{"redist_type": "static", "route_map": "rmap_ipv6"}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured"
        "summary address on R0 and only one route is sent to R1. Verify that "
        "show ip ospf summary should show the configure summaries."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Configure metric type as 1 in route map.")

    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv6": [
                    {
                        "seq_id": "1",
                        "action": "permit",
                        "set": {"metric-type": "type-1"},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with metric type 2."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Un configure metric type from route map.")

    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv6": [
                    {
                        "action": "permit",
                        "seq_id": "1",
                        "set": {"metric-type": "type-1", "delete": True},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with metric type 2."
    )
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Change rule from permit to deny in prefix list.")
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv6": {
                    "pf_list_1_ipv6": [
                        {"seqid": 10, "network": "any", "action": "deny"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that previously originated summary lsa "
        "is withdrawn from the neighbor."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    step("summary route has delay of 5 secs, wait for 5 secs")

    sleep(5)

    result = verify_ospf6_rib(tgen, dut, input_dict_summary, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict_summary, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    write_test_footer(tc_name)


def test_ospfv3_type5_summary_tc51_p2(request):
    """OSPF CLI Show.

    verify ospf ASBR summary config and show commands behaviours.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure all the supported OSPF ASBR summary commands on DUT.")
    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "32",
                        "tag": 4294967295,
                    },
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "16",
                        "advertise": True,
                    },
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "24",
                        "advertise": False,
                    },
                    {
                        "prefix": SUMMARY["ipv6"][0].split("/")[0],
                        "mask": "24",
                        "advertise": False,
                    },
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure and re configure all the commands 10 times in a loop.")

    for _ in range(0, 10):
        ospf_summ_r1 = {
            "r0": {
                "ospf6": {
                    "summary-address": [
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "8",
                            "tag": 4294967295,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "16",
                            "advertise": True,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "24",
                            "advertise": False,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "24",
                            "advertise": False,
                        },
                    ]
                }
            }
        }
        result = create_router_ospf(tgen, topo, ospf_summ_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        ospf_summ_r1 = {
            "r0": {
                "ospf6": {
                    "summary-address": [
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "8",
                            "tag": 4294967295,
                            "delete": True,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "16",
                            "advertise": True,
                            "delete": True,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "24",
                            "advertise": False,
                            "delete": True,
                        },
                        {
                            "prefix": SUMMARY["ipv6"][0].split("/")[0],
                            "mask": "24",
                            "advertise": False,
                            "delete": True,
                        },
                    ]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify the show commands")

    input_dict = {
        SUMMARY["ipv6"][3]: {
            "summaryAddress": SUMMARY["ipv6"][3],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 0,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    write_test_footer(tc_name)


def test_ospfv3_type5_summary_tc49_p2(request):
    """OSPF summarisation Chaos."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    protocol = "ospf"

    step(
        "Configure 5 static routes from the same network on R0"
        "5 static routes from different networks and redistribute in R0"
    )
    input_dict_static_rtes = {
        "r0": {
            "static_routes": [
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Configure External Route summary in R0 to summarise 5  routes to one route.")

    ospf_summ_r1 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "32"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there  peer.")
    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r0")
    start_router(tgen, "r0")

    step(
        "Verify that external routes are summarised to configured summary "
        "address on R0 after 5 secs of delay timer expiry and only one "
        "route is sent to R1."
    )
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][0]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][0]: {
            "summaryAddress": SUMMARY["ipv6"][0],
            "metricType": "E2",
            "Metric": 20,
            "Tag": 0,
            "externalRouteCount": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there  peer.")
    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv6"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error:  Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed Error: Routes still present in RIB".format(tc_name)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
