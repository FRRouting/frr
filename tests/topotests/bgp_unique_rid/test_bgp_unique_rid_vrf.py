#!/usr/bin/env python

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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

import sys
import time
import pytest
import inspect
import os
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

"""Following tests are covered to test bgp unique rid functionality.
1. Verify iBGP session when same and different router ID is configured in user VRF(GREEN).
2. Verify eBGP session when same and different router ID is configured in user vrf (VRF RED)
3. Verify two different eBGP sessions initiated with same router ID in user VRf (RED and GREEN)
"""

#################################
# TOPOLOGY
#################################
"""

                    +-------+
         +--------- |  R2   |
         |          +-------+
         |iBGP           |
     +-------+           |
     |  R1   |           |iBGP
     +-------+           |
         |               |
         |    iBGP   +-------+   eBGP   +-------+
         +---------- |  R3   |========= |  R4   |
                     +-------+          +-------+
                        |
                        |eBGP
                        |
                    +-------+
                    |  R5   |
                    +-------+


"""

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,
    write_test_header,
    step,
    write_test_footer,
    check_address_types,
    reset_config_on_routers,
    check_router_status,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    clear_bgp_and_verify,
)

# Global variables
topo = None
bgp_convergence = False
NETWORK = {
    "ipv4": [
        "192.168.20.1/32",
        "192.168.20.2/32",
        "192.168.21.1/32",
        "192.168.21.2/32",
        "192.168.22.1/32",
        "192.168.22.2/32",
    ],
    "ipv6": [
        "fc07:50::1/128",
        "fc07:50::2/128",
        "fc07:150::1/128",
        "fc07:150::2/128",
        "fc07:1::1/128",
        "fc07:1::2/128",
    ],
}

bgp_convergence = False
ADDR_TYPES = check_address_types()


def setup_module(mod):
    """setup_module.

    Set up the pytest environment
    * `mod`: module name
    """
    global topo
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_unique_rid_vrf.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence
    global ADDR_TYPES

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "setup_module :Failed \n Error:" " {}".format(
        bgp_convergence
    )
    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
# Tests starting
#####################################################


def test_bgp_unique_rid_ebgp_vrf_p0():
    """
    TC: 1
    Verify iBGP session when same and different router ID is configured in user VRF(GREEN).
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Base config should be up, verify using BGP convergence on all \
    the routers for IPv4 and IPv6 nbrs"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R4 and R3 10.10.10.10")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
        "r4": {"bgp": {"router_id": "10.10.10.10", "local_as": 200, "vrf": "RED"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R5 and R3 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
        "r5": {"bgp": {"router_id": "10.10.10.10", "local_as": 300, "vrf": "RED"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("modify the router id on r3 to different router id (11.11.11.11)")
    input_dict = {
        "r3": {"bgp": {"router_id": "11.11.11.11", "local_as": 100, "vrf": "RED"}}
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Reset bgp process")
    step("Verify neighbours are in ESTAB state.")
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, router="r3")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear ip bgp process with *")
    step("Verify neighbours are in ESTAB state.")
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure neighbours between R3 and R4 in EVPN address family.")
    input_dict = {
        "r3": {
            "bgp": {
                "local_as": 100,
                "vrf": "RED",
                "address_family": {
                    "l2vpn": {
                        "evpn": {
                            "advertise": {
                                "ipv4": {"unicast": {}},
                                "ipv6": {"unicast": {}},
                            }
                        }
                    }
                },
            }
        },
        "r4": {
            "bgp": {
                "local_as": 200,
                "vrf": "RED",
                "address_family": {
                    "l2vpn": {
                        "evpn": {
                            "advertise": {
                                "ipv4": {"unicast": {}},
                                "ipv6": {"unicast": {}},
                            }
                        }
                    }
                },
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_unique_rid_ibgp_vrf_p0():
    """
    TC: 2
    Verify eBGP session when same and different router ID is configured in user vrf (VRF RED)
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Base config should be up, verify using BGP convergence on all \
    the routers for IPv4 and IPv6 nbrs"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R1 and R3 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
        "r1": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R2 and R3 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
        "r2": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("modify the router id on r3 to different router id (11.11.11.11)")
    input_dict = {
        "r3": {"bgp": {"router_id": "11.11.11.11", "local_as": 100, "vrf": "RED"}}
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo, dut="r3")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Reset bgp process")
    step("Verify neighbours are in ESTAB state.")
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear ip bgp process with *")
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_unique_rid_multi_bgp_nbrs_vrf_p0():
    """
    TC: 3
    Verify two different eBGP sessions initiated with same router ID in user VRf (RED and GREEN)

    """
    tgen = get_topogen()
    global bgp_convergence, topo

    if bgp_convergence is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step(
        "Base config should be up, verify using BGP convergence on all \
    the routers for IPv4 and IPv6 nbrs"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R3, R4 and R5 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10", "local_as": 100, "vrf": "RED"}},
        "r4": {"bgp": {"router_id": "10.10.10.10", "local_as": 200, "vrf": "RED"}},
        "r5": {"bgp": {"router_id": "10.10.10.10", "local_as": 300, "vrf": "RED"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure the same IP address on on R4 and R5 loopback address and \
            change the neighborship to loopback neighbours between R3 to R4 \
            and R3 to R5 respectively."
    )

    topo1 = deepcopy(topo)

    for rtr in ["r4", "r5"]:
        topo1["routers"][rtr]["links"]["lo"]["ipv4"] = "192.168.1.1/32"

    topo1["routers"]["r3"]["links"]["lo"]["ipv4"] = "192.168.1.3/32"
    build_config_from_json(tgen, topo1, save_bkup=False)

    step(
        "change the neighborship to loopback neighbours between R3 to R4 and R3 to R5 respectively."
    )
    for rtr in ["r4", "r5"]:
        configure_bgp_on_rtr = {
            "r3": {
                "bgp": {
                    "local_as": 100,
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"neighbor": {rtr: {"dest_link": {"lo": {}}}}}
                        }
                    },
                },
            }
        }
        result = create_router_bgp(tgen, topo1, configure_bgp_on_rtr)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    bgp_convergence = verify_bgp_convergence(tgen, topo1, dut="r3")
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Change the IP address on the R4 loopback.")
    topo1["routers"]["r4"]["links"]["lo"]["ipv4"] = "192.168.1.4/32"
    build_config_from_json(tgen, topo1, save_bkup=False)

    step("Verify neighbours should be again in ESTAB state. (show ip bgp neighbours)")
    bgp_convergence = verify_bgp_convergence(tgen, topo1, dut="r3")
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Clear ip bgp process with *")
    result = clear_bgp_and_verify(tgen, topo, router="r3")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
