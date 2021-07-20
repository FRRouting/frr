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


"""OSPF Summarisation Functionality Automation."""
import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
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
    get_topojson,
    stop_topology,
)
from lib.topolog import logger
from lib.topobuild import build_topo_from_json
from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf6_database,
    verify_ospf_summary,
    verify_ospf6_neighbor,
    verify_ospf6_rib,
    create_router_ospf,
)

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
NETWORK3 = {
    "ipv4": [
        "13.0.20.1/32",
        "13.0.20.2/32",
        "13.0.20.3/32",
        "13.0.20.4/32",
        "13.0.20.5/32",
    ],
    "ipv6": [
        "2013:0:20::1/128",
        "2013:0:20::2/128",
        "2013:0:20::3/128",
        "2013:0:20::4/128",
        "2013:0:20::5/128",
    ],
}
SUMMARY = {
    "ipv4": ["11.0.20.1/8", "12.0.0.0/8", "13.0.0.0/8", "11.0.0.0/8"],
    "ipv6": ["2011::/8", "2012::/8", "2013::/8", "2011::0/8"],
}
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


class CreateTopo(Topo):
    """
    Test topology builder.

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function."""
        tgen = get_topogen(self)

        # Read the topo.json file
        topo = get_topojson(os.path.realpath(__file__))

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
    tgen = Topogen(CreateTopo, mod)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)
    topo = tgen.topojson
    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # Api call verify whether OSPF is converged
    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    stop_topology(tgen)


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
                    "redistribute": [{"redist_type": "connected", "delete": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase: Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospfv3_type5_summary_tc44_p0(request):
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
                {"network": NETWORK["ipv6"], "next_hop": "blackhole"},
                {"network": NETWORK2["ipv6"], "next_hop": "blackhole"},
            ]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that routes are learnt on R1.")
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step(
        "Configure External Route summary in R0 to summarise 5" " routes to one route."
    )

    ospf_summ_r0 = {
        "r0": {
            "ospf6": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][0].split("/")[0], "mask": "8"}
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

    step(
        "Configure summary & redistribute static/connected route with " "metric type 2"
    )

    input_dict_summary = {"r0": {"static_routes": [{"network": SUMMARY["ipv6"][3]}]}}
    dut = "r1"

    result = verify_ospf6_rib(tgen, dut, input_dict_summary)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict_summary, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    step("Verify that show ip ospf summary should show the summaries.")
    input_dict = {
        SUMMARY["ipv6"][3]: {
            "Summary address": SUMMARY["ipv6"][3],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Learn type 7 lsa from neighbours")

    dut = "r1"
    protocol = "ospf"

    red_static(dut)
    input_dict_static_rtes = {
        "r1": {
            "static_routes": [{"network": NETWORK3["ipv6"], "next_hop": "blackhole"}]
        }
    }
    result = create_static_routes(tgen, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that routes are learnt on R0.")
    dut = "r0"

    result = verify_ospf6_rib(tgen, dut, input_dict_static_rtes)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    result = verify_rib(tgen, "ipv6", dut, input_dict_static_rtes, protocol=protocol)
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Routes is missing in RIB".format(tc_name)

    ospf_summ_r0 = {
        "r0": {
            "ospf": {
                "summary-address": [
                    {"prefix": SUMMARY["ipv6"][2].split("/")[0], "mask": "8"}
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_summ_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that type7 LSAs received from neighbor are not summarised.")
    input_dict = {
        "2013::0/8": {
            "Summary address": "2013::0/8",
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 0,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    step("Verify that already originated summary is intact.")
    input_dict = {
        SUMMARY["ipv6"][3]: {
            "Summary address": SUMMARY["ipv6"][3],
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5,
        }
    }
    dut = "r0"
    result = verify_ospf_summary(tgen, topo, dut, input_dict, ospf="ospf6")
    assert (
        result is True
    ), "Testcase {} : Failed" "Error: Summary missing in OSPF DB".format(tc_name)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
