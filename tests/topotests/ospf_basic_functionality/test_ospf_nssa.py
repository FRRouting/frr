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


"""OSPF Basic Functionality Automation."""
import ipaddress
from lib.ospf import (
    verify_ospf_neighbor,
    config_ospf_interface,
    clear_ospf,
    verify_ospf_rib,
    create_router_ospf,
    verify_ospf_interface,
    redistribute_ospf,
)
from lib.topojson import build_topo_from_json, build_config_from_json
from lib.topolog import logger
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
    create_route_maps,
    shutdown_bringup_interface,
    create_interfaces_cfg,
    topo_daemons,
)
from ipaddress import IPv4Address
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo
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

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/ospf_nssa.json".format(CWD)
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
1. OSPF Learning - Verify OSPF can learn different types of LSA and
   processes them.[Edge learning different types of LSAs]
2. Verify that ospf non back bone area can be configured as NSSA area
3. Verify that ospf NSSA area DUT is capable receiving & processing
   Type7 N2 route.
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


# ##################################
# Test cases start here.
# ##################################


def test_ospf_learning_tc15_p0(request):
    """Verify OSPF can learn different types of LSA and processes them.

    OSPF Learning : Edge learning different types of LSAs.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure area 1 as NSSA Area")

    reset_config_on_routers(tgen)

    step("Verify that Type 3 summary LSA is originated for the same Area 0")
    ip = topo["routers"]["r1"]["links"]["r3-link0"]["ipv4"]
    ip_net = str(ipaddress.ip_interface(u"{}".format(ip)).network)

    dut = "r0"
    input_dict = {
        "r1": {
            "static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N IA"}]
        }
    }

    dut = "r0"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 5, "next_hop": "Null0"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute static route in R2 ospf.")
    dut = "r2"
    redistribute_ospf(tgen, topo, dut, "static")

    step("Verify that Type 5 LSA is originated by R2.")
    dut = "r0"
    protocol = "ospf"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that R0 receives Type 4 summary LSA.")
    dut = "r0"
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 1, "routeType": "N E2"}
            ]
        }
    }

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Change area 1 as non nssa area (on the fly changing area" " type on DUT).")

    for rtr in ["r1", "r2", "r3"]:
        input_dict = {
            rtr: {"ospf": {"area": [{"id": "0.0.0.2", "type": "nssa", "delete": True}]}}
        }
        result = create_router_ospf(tgen, topo, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that OSPF neighbours are reset after changing area type.")
    step("Verify that ABR R2 originates type 5 LSA in area 1.")
    step("Verify that route is calculated and installed in R1.")

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv4"][0], "no_of_ip": 1, "routeType": "N E2"}
            ]
        }
    }

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
