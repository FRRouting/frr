#!/usr/bin/python

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
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


"""OSPF Summarisation Functionality Automation."""
import os
import sys
import time
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
from lib.topogen import Topogen, get_topogen
import ipaddress
from time import sleep

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    kill_router_daemons,
    write_test_footer,
    reset_config_on_routers,
    stop_router,
    start_router,
    verify_rib,
    create_static_routes,
    step,
    start_router_daemons,
    create_route_maps,
    shutdown_bringup_interface,
    topo_daemons,
    create_prefix_lists,
    create_route_maps,
    create_interfaces_cfg,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    clear_ospf,
    verify_ospf_rib,
    create_router_ospf,
    verify_ospf_summary,
)

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/ospf_asbr_summary_topo1.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

NETWORK = {
    "ipv4": [
        "11.0.20.1/32",
        "11.0.20.2/32",
        "11.0.20.3/32",
        "11.0.20.4/32",
        "11.0.20.5/32",
    ]
}
NETWORK_11 = {"ipv4": ["11.0.20.6/32", "11.0.20.7/32"]}

NETWORK2 = {
    "ipv4": [
        "12.0.20.1/32",
        "12.0.20.2/32",
        "12.0.20.3/32",
        "12.0.20.4/32",
        "12.0.20.5/32",
    ]
}
SUMMARY = {"ipv4": ["11.0.0.0/8", "12.0.0.0/8", "11.0.0.0/24"]}
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
2. OSPF summarisation with metric type 2.
3. OSPF summarisation with Tag option
4. OSPF summarisation with advertise and no advertise option
5. OSPF summarisation Chaos.
6. OSPF summarisation with route map filtering.
7. OSPF summarisation with route map modification of metric type.
8. OSPF CLI Show  verify ospf ASBR summary config and show commands behaviours.
"""


class CreateTopo(Topo):
    """
    Test topology builder.

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function."""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


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
    tgen = Topogen(CreateTopo, mod.__name__)
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
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
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
        ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    else:
        ospf_red = {
            dut: {"ospf": {"redistribute": [{"redist_type": "static", "delete": True}]}}
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
        ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": "connected"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf": {"redistribute": [{"redist_type": "connected", "delete": True}]}
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospf_type5_summary_tc43_p0(request):
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
                {"network": NETWORK["ipv4"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv4"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv4", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step(
        "Configure External Route summary in R0 to summarise 5" " routes to one route."
    )
    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "8"}
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
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv4"][0]}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv4"][0]: {
            "Summary address": SUMMARY["ipv4"][0],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Change the summary address mask to lower match (ex - 16 to 8)")
    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "16"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "11.0.0.0/16": {
            "Summary address": "11.0.0.0/16",
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "11.0.0.0/16"}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step("Change the summary address mask to higher match (ex - 8 to 24)")
    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "24"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "11.0.0.0/16": {
            "Summary address": "11.0.0.0/24",
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 0,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )
    step("Configure 2 summary address with different mask of same network.")
    step(
        "Verify that external routes(static / connected) are summarised "
        "to configured summary address with highest match."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "11.0.0.0/16"}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step(" Un configure one of the summary address.")
    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {
                        "prefix": SUMMARY["ipv4"][0].split("/")[0],
                        "mask": "24",
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that external routes(static / connected) are summarised"
        " to configured summary address with newly configured mask."
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": "11.0.0.0/16"}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "24"}
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
    input_dict_summary = {"r0": {"static_routes": [{"network": "11.0.0.0/16"}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    write_test_footer(tc_name)


def test_ospf_type5_summary_tc48_p0(request):
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
                {"network": NETWORK["ipv4"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv4"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    red_static(dut)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv4", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step(
        "Configure External Route summary in R0 to summarise 5" " routes to one route."
    )

    ospf_summ_r1 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv4"][0].split("/")[0], "mask": "8"}
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
    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv4"][0]}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv4"][0]: {
            "Summary address": SUMMARY["ipv4"][0],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that originally advertised routes are withdraw from there" " peer.")
    input_dict = {
        "r0": {"static_routes": [{"network": NETWORK["ipv4"], "next_hop": "blackhole"}]}
    }
    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Error: " "Routes still present in OSPF RIB {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv4", dut, input_dict, protocol=protocol, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed" "Error: Routes still present in RIB".format(tc_name)

    step(
        "Configure route map and & rule to permit configured summary address,"
        " redistribute static & connected routes with the route map."
    )
    step("Configure prefixlist to permit the static routes, add to route map.")
    # Create ip prefix list
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
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
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "match": {"ipv4": {"prefix_lists": "pf_list_1_ipv4"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, routemaps)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_red_r1 = {
        "r0": {
            "ospf": {
                "redistribute": [{"redist_type": "static", "route_map": "rmap_ipv4"}]
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

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv4"][0]}]}}
    dut = "r1"

    result = verify_ospf_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    input_dict = {
        SUMMARY["ipv4"][0]: {
            "Summary address": SUMMARY["ipv4"][0],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Configure metric type as 1 in route map.")

    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [{"action": "permit", "set": {"metric-type": "type-1"}}]
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
        SUMMARY["ipv4"][0]: {
            "Summary address": SUMMARY["ipv4"][0],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Un configure metric type from route map.")

    routemaps = {
        "r0": {
            "route_maps": {
                "rmap_ipv4": [
                    {
                        "action": "permit",
                        "set": {"metric-type": "type-1"},
                        "delete": True,
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
        SUMMARY["ipv4"][0]: {
            "Summary address": SUMMARY["ipv4"][0],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Change rule from permit to deny in prefix list.")
    pfx_list = {
        "r0": {
            "prefix_lists": {
                "ipv4": {
                    "pf_list_1_ipv4": [
                        {"seqid": 10, "network": "any", "action": "deny"}
                    ]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, pfx_list)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
