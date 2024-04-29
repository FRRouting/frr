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
from copy import deepcopy
import ipaddress
from lib.ospf import (
    verify_ospf6_neighbor,
    config_ospf6_interface,
    clear_ospf,
    verify_ospf6_rib,
    verify_ospf6_interface,
    verify_ospf6_database,
    create_router_ospf,
)

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    clear_bgp_and_verify,
    verify_bgp_rib,
)
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
    check_router_status,
)
from ipaddress import IPv4Address
from lib.topolog import logger
from lib.topojson import build_config_from_json


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

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
    json_file = "{}/ospfv3_nssa2.json".format(CWD)
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
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


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


# ##################################
# Test cases start here.
# ##################################


def test_ospfv3_nssa_tc26_p0(request):
    """Verify that ospf non back bone area can be configured as NSSA area"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure ospf area 2 on r0 , r1 & r4, make the area 2 as NSSA area")

    reset_config_on_routers(tgen)

    input_dict = {
        "r2": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 5, "next_hop": "Null0"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute static route in R2 ospf.")
    dut = "r2"
    red_static(dut)

    step("Verify that Type 5 LSA is originated by R2.")
    dut = "r0"
    protocol = "ospf6"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Un configure redistribute command in R4")
    dut = "r2"
    red_static(dut, config=False)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 1, "routeType": "Network"}
            ]
        }
    }

    step("Configure area 0 on interface of r2 connecting to r1")

    input_dict = {
        "r2": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r2"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.2"},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r2"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.0"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbor goes down between r2 and r1.")
    result = verify_ospf6_neighbor(tgen, topo, dut="r2", expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Nbrs are not down Error: {}".format(tc_name, result)

    step("Now configure area 0 on interface of r1 connecting to r2.")

    input_dict = {
        "r1": {
            "links": {
                "r2": {
                    "interface": topo["routers"]["r1"]["links"]["r2"]["interface"],
                    "ospf6": {"area": "0.0.0.2"},
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
                "r2": {
                    "interface": topo["routers"]["r1"]["links"]["r2"]["interface"],
                    "ospf6": {"area": "0.0.0.0"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that ospf neighbour comes up between r2 and r1.")
    result = verify_ospf6_neighbor(tgen, topo, dut="r2")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure area 2 on interface of r2 connecting to r1.")

    input_dict = {
        "r2": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r2"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.0"},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r2"]["links"]["r1"]["interface"],
                    "ospf6": {"area": "0.0.0.2"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbor goes down between r2 and r1.")
    result = verify_ospf6_neighbor(tgen, topo, dut="r2", expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Nbrs are not down Error: {}".format(tc_name, result)

    step("Now configure area 2 on interface of r1 connecting to r2.")

    input_dict = {
        "r1": {
            "links": {
                "r2": {
                    "interface": topo["routers"]["r1"]["links"]["r2"]["interface"],
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
                "r2": {
                    "interface": topo["routers"]["r1"]["links"]["r2"]["interface"],
                    "ospf6": {"area": "0.0.0.2"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that ospf neighbour comes up between r2 and r1.")
    result = verify_ospf6_neighbor(tgen, topo, dut="r2")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_learning_tc15_p0(request):
    """Verify OSPF can learn different types of LSA and processes them.

    OSPF Learning : Edge learning different types of LSAs.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure area 1 as NSSA Area")

    reset_config_on_routers(tgen)

    step("Verify that Type 3 summary LSA is originated for the same Area 0")
    ip = topo["routers"]["r1"]["links"]["r3-link0"]["ipv6"]
    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)

    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": ip_net,
                    "no_of_ip": 1,
                    "routeType": "Network",
                    "pathtype": "Inter-Area",
                }
            ]
        }
    }

    dut = "r0"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    protocol = "ospf6"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r2": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 5, "next_hop": "Null0"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute static route in R2 ospf.")
    dut = "r2"
    red_static(dut)

    step("Verify that Type 5 LSA is originated by R2.")
    dut = "r0"
    protocol = "ospf6"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 1, "routeType": "Network"}
            ]
        }
    }

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change area 1 as non nssa area (on the fly changing area  type on DUT).")

    for rtr in ["r1", "r2", "r3"]:
        input_dict = {
            rtr: {
                "ospf6": {"area": [{"id": "0.0.0.2", "type": "nssa", "delete": True}]}
            }
        }
        result = create_router_ospf(tgen, topo, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that OSPF neighbours are reset after changing area type.")
    step("Verify that ABR R2 originates type 5 LSA in area 1.")
    step("Verify that R1 installs type 5 lsa in its database.")
    step("Verify that route is calculated and installed in R1.")

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 1, "routeType": "Network"}
            ]
        }
    }

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


# As per internal discussion, this script has to be removed as translator
# function is not supported, for more details kindly check this PR 2565570
def ospfv3_nssa_tc27_p0(request):
    """
    OSPF NSSA.

    Verify that ospf NSSA area DUT is capable receiving & processing
    Type7 N2 route.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo
    step("Bring up the base config as per the topology")
    step("Configure ospf area 2 on r0 , r1 & r4, make the area 2 as NSSA area")

    reset_config_on_routers(tgen)

    input_dict = {
        "r2": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 5, "next_hop": "Null0"}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Redistribute static route in R2 ospf.")
    dut = "r2"
    red_static(dut)

    step("Verify that Type 5 LSA is originated by R2.")
    dut = "r0"
    protocol = "ospf6"
    result = verify_rib(tgen, "ipv6", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Un configure redistribute command in R4")
    dut = "r2"
    red_static(dut, config=False)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": NETWORK["ipv6"][0], "no_of_ip": 1, "routeType": "Network"}
            ]
        }
    }

    dut = "r0"
    result = verify_ospf6_rib(tgen, dut, input_dict, expected=False)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    result = verify_rib(
        tgen, "ipv6", dut, input_dict, protocol=protocol, expected=False
    )
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
