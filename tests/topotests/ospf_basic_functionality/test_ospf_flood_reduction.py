#!/usr/bin/python

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
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
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]
# Global variables
topo = None

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topolog import logger
from lib.topojson import build_config_from_json

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    step,
    topo_daemons,
    shutdown_bringup_interface,
    check_router_status,
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    create_static_routes,
    step,
    shutdown_bringup_interface,
    check_router_status,
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    stop_router,
    start_router,
    step,
    create_static_routes,
    kill_router_daemons,
    check_router_status,
    start_router_daemons,
)
from lib.topolog import logger
from lib.topogen import Topogen, get_topogen

from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    clear_ospf,
    create_router_ospf,
    verify_ospf_database,
    get_ospf_database,
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
1. Verify OSPF Flood reduction functionality with ospf enabled on process level.
2. Verify OSPF Flood reduction functionality with ospf enabled on area level.
3. Verify OSPF Flood reduction functionality between different area's.
4. Verify OSPF Flood reduction functionality with ospf enabled on process level with default lsa refresh timer.
5. Chaos - Verify OSPF TTL GTSM and flood  reduction functionality in chaos scenarios.
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
    json_file = "{}/ospf_flood_reduction.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen)

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
    """Local def for Redstribute static routes inside ospf."""
    global topo
    tgen = get_topogen()
    if config:
        ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": "static"}]}}}
    else:
        ospf_red = {
            dut: {
                "ospf": {
                    "redistribute": [{"redist_type": "static", "del_action": True}]
                }
            }
        }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################
def test_ospf_flood_red_tc1_p0(request):
    """Verify OSPF Flood reduction functionality with ospf enabled on process level."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo

    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)
    red_static("r0")
    step("Base config should be up, verify using OSPF convergence on all the routers")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Enable flood reduction in process level on R0")
    ospf_flood = {"r0": {"ospf": {"flood-reduction": True}}}
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Verify that ospf lsa's are set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure the custom refresh timer")
    ospf_flood = {"r0": {"ospf": {"lsa-refresh": 120}}}
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Enable flood. reduction in all the routers of the topology.")
    for rtr in topo["routers"].keys():
        ospf_flood = {rtr: {"ospf": {"lsa-refresh": 120, "flood-reduction": True}}}
        result = create_router_ospf(tgen, topo, ospf_flood)
        assert result is True, "Testcase : Failed \n Error: {}".format(result)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lsa's are set with dc bit 1.")
    for rtr in topo["routers"]:
        dut = rtr
        lsid = "{}".format(topo["routers"][rtr]["ospf"]["router_id"])
        input_dict_db = {
            "routerId": lsid,
            "areas": {
                "0.0.0.0": {
                    "routerLinkStates": [
                        {
                            "lsaId": lsid,
                            "options": "*|-|DC|-|-|-|E|-",
                        },
                    ]
                }
            },
        }
        result = verify_ospf_database(
            tgen, topo, dut, input_dict_db, lsatype="router", rid=lsid
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    # this wait is put so that we wait for 5secs to check if lsa is refreshed.
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    assert (result1 == result2) is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Disable flood reduction in R0.")
    ospf_flood = {
        "r0": {"ospf": {"flood-reduction": True, "del_flood_reduction": True}}
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    clear_ospf(tgen, "r0")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lea's are not set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen,
        topo,
        dut,
        input_dict_db,
        lsatype="router",
        rid="100.1.1.0",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: OSPF LSA should not be set with DC bit in {} \n "
        "Found: {}".format(tc_name, dut, result)
    )
    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    if result2 is not result1:
        result = True
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Enable flood reduction on each router with 10 secs delay of between each router."
    )
    for rtr in topo["routers"].keys():
        ospf_flood = {rtr: {"ospf": {"lsa-refresh": 120, "flood-reduction": True}}}
        sleep(10)
        result = create_router_ospf(tgen, topo, ospf_flood)
        assert result is True, "Testcase : Failed \n Error: {}".format(result)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    step("Verify that LSA's are not refreshed. Do not age bit should be set to 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify OSPF neighborship when OSPF flood reduction  is configured and ospf process is restarted"
    )

    step("Kill OSPFd daemon on R0.")
    kill_router_daemons(tgen, "r0", ["ospfd"])
    start_router_daemons(tgen, "r0", ["ospfd"])

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that LSA's are not refreshed. Do not age bit should be set to 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_flood_red_tc2_p0(request):
    """Verify OSPF Flood reduction functionality with ospf enabled on area level."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo

    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)
    red_static("r0")
    step("Base config should be up, verify using OSPF convergence on all the routers")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Enable flood reduction in area level on R0 in area 0")
    ospf_flood = {
        "r0": {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Verify that ospf lsa's are set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure the custom refresh timer")
    ospf_flood = {"r0": {"ospf": {"lsa-refresh": 120}}}
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Enable flood. reduction in all the routers of the topology.")
    for rtr in topo["routers"].keys():
        ospf_flood = {
            rtr: {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
        }
        result = create_router_ospf(tgen, topo, ospf_flood)
        assert result is True, "Testcase : Failed \n Error: {}".format(result)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lsa's are set with dc bit 1.")
    for rtr in topo["routers"]:
        dut = rtr
        lsid = "{}".format(topo["routers"][rtr]["ospf"]["router_id"])
        input_dict_db = {
            "routerId": lsid,
            "areas": {
                "0.0.0.0": {
                    "routerLinkStates": [
                        {
                            "lsaId": lsid,
                            "options": "*|-|DC|-|-|-|E|-",
                        },
                    ]
                }
            },
        }
        result = verify_ospf_database(
            tgen, topo, dut, input_dict_db, lsatype="router", rid=lsid
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    assert (result1 == result2) is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Disable flood reduction in R0.")
    ospf_flood = {
        "r0": {
            "ospf": {
                "area": [{"id": "0.0.0.0", "flood-reduction": True, "delete": True}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    clear_ospf(tgen, "r0")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lea's are not set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen,
        topo,
        dut,
        input_dict_db,
        lsatype="router",
        rid="100.1.1.0",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: OSPF LSA should not be set with DC bit in {} \n "
        "Found: {}".format(tc_name, dut, result)
    )
    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    if result2 is not result1:
        result = True
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Enable flood reduction on each router with 10 secs delay of between each router."
    )
    for rtr in topo["routers"].keys():
        ospf_flood = {
            rtr: {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
        }
        sleep(10)
        result = create_router_ospf(tgen, topo, ospf_flood)
        assert result is True, "Testcase : Failed \n Error: {}".format(result)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    step("Verify that LSA's are not refreshed. Do not age bit should be set to 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_flood_red_tc3_p0(request):
    """Verify OSPF Flood reduction functionality between different area's"""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    global topo

    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)
    red_static("r0")
    step("Base config should be up, verify using OSPF convergence on all the routers")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    input_dict = {
        "r0": {
            "static_routes": [
                {
                    "network": NETWORK["ipv4"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Enable flood reduction in area level on R0 in area 0")
    ospf_flood = {
        "r0": {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Verify that ospf lsa's are set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure the custom refresh timer")
    ospf_flood = {"r0": {"ospf": {"lsa-refresh": 120}}}
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step(
        "Enable flood. reduction in all the routers of the topology in area 0. Redistribute static route in area 0 R1 and area1 in R2."
    )
    for rtr in topo["routers"].keys():
        ospf_flood = {
            rtr: {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
        }
        result = create_router_ospf(tgen, topo, ospf_flood)
        assert result is True, "Testcase : Failed \n Error: {}".format(result)

    sleep(10)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lsa's are set with dc bit 1.")
    for rtr in topo["routers"]:
        dut = rtr
        lsid = "{}".format(topo["routers"][rtr]["ospf"]["router_id"])
        input_dict_db = {
            "routerId": lsid,
            "areas": {
                "0.0.0.0": {
                    "routerLinkStates": [
                        {
                            "lsaId": lsid,
                            "options": "*|-|DC|-|-|-|E|-",
                        },
                    ]
                }
            },
        }
        result = verify_ospf_database(
            tgen, topo, dut, input_dict_db, lsatype="router", rid=lsid
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    assert (result1 == result2) is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Enable flood reduction in area 1.")

    ospf_flood = {
        "r0": {"ospf": {"area": [{"id": "0.0.0.0", "flood-reduction": True}]}}
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r1": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True},
                    {"id": "0.0.0.1", "flood-reduction": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r2": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True},
                    {"id": "0.0.0.1", "flood-reduction": True},
                    {"id": "0.0.0.2", "flood-reduction": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r3": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True},
                    {"id": "0.0.0.2", "flood-reduction": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lea's are  set with dc bit 1.")
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.1",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.1",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.1"
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.1",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.1", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.1"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.1"
    )

    if result2 is result1:
        result = True
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Disable flood reduction in R0.")

    ospf_flood = {
        "r0": {
            "ospf": {
                "area": [{"id": "0.0.0.0", "flood-reduction": True, "delete": True}]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r1": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True, "delete": True},
                    {"id": "0.0.0.1", "flood-reduction": True, "delete": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r2": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True, "delete": True},
                    {"id": "0.0.0.1", "flood-reduction": True, "delete": True},
                    {"id": "0.0.0.2", "flood-reduction": True, "delete": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_flood = {
        "r3": {
            "ospf": {
                "area": [
                    {"id": "0.0.0.0", "flood-reduction": True, "delete": True},
                    {"id": "0.0.0.2", "flood-reduction": True, "delete": True},
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_flood)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    clear_ospf(tgen, "r0")

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("Verify that ospf lea's are not set with dc bit 1.")
    dut = "r0"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsaId": "100.1.1.0",
                        "options": "*|-|DC|-|-|-|E|-",
                    },
                ]
            }
        },
    }
    result = verify_ospf_database(
        tgen,
        topo,
        dut,
        input_dict_db,
        lsatype="router",
        rid="100.1.1.0",
        expected=False,
    )

    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: OSPF LSA should not be set with DC bit in {} \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("Wait for 120 secs and verify that LSA's are not refreshed. ")
    # get LSA age
    dut = "r1"
    input_dict_db = {
        "routerId": "100.1.1.0",
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {"lsaId": "100.1.1.0", "lsaAge": "get"},
                ]
            }
        },
    }
    sleep(10)

    result1 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )
    sleep(5)
    result2 = get_ospf_database(
        tgen, topo, dut, input_dict_db, lsatype="router", rid="100.1.1.0"
    )

    if result2 is not result1:
        result = True
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
