#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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
1. Verify eBGP session when same and different router ID is configured.
2. Verify iBGP session when same and different router ID is configured.
3. Verify two different eBGP sessions initiated with same router ID.
4. Chaos - Verify bgp unique rid functionality in chaos scenarios.
5. Chaos - Verify bgp unique rid functionality when router reboots with same loopback id.
6. Chaos - Verify bgp unique rid functionality when router reboots without any ip addresses.
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

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.staticd]

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,
    write_test_header,
    step,
    write_test_footer,
    verify_rib,
    check_address_types,
    reset_config_on_routers,
    check_router_status,
    stop_router,
    kill_router_daemons,
    start_router_daemons,
    start_router,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    clear_bgp_and_verify,
)
from lib.ospf import verify_ospf_neighbor, clear_ospf

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
routerid = {"ipv4": "10.10.10.14", "ipv6": "fd00:0:0:3::2"}


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
    json_file = "{}/bgp_unique_rid.json".format(CWD)
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


def test_bgp_unique_rid_ebgp_p0():
    """
    TC: 1
    Verify eBGP session when same and different router ID is configured.
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
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r4": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure the same router id between R5 and R3 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r5": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("modify the router id on r3 to different router id (11.11.11.11)")
    input_dict = {"r3": {"bgp": {"router_id": "11.11.11.11"}}}
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Reset bgp process")
    step("Verify neighbours are in ESTAB state.")
    dut = "r3"
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear ip bgp process with *")
    step("Verify neighbours are in ESTAB state.")
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure neighbours between R3 and R4 in EVPN address family.")
    input_dict = {
        "r3": {
            "bgp": {
                "address_family": {
                    "l2vpn": {
                        "evpn": {
                            "advertise": {
                                "ipv4": {"unicast": {}},
                                "ipv6": {"unicast": {}},
                            }
                        }
                    }
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "l2vpn": {
                        "evpn": {
                            "advertise": {
                                "ipv4": {"unicast": {}},
                                "ipv6": {"unicast": {}},
                            }
                        }
                    }
                }
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_unique_rid_ibgp_p0():
    """
    TC: 2
    Verify iBGP session when same and different router ID is configured.
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
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r1": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in idle state.")
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("Configure the same router id between R2 and R3 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r2": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in idle state.")
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("modify the router id on r3 to different router id (11.11.11.11)")
    input_dict = {"r3": {"bgp": {"router_id": "11.11.11.11"}}}
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


def test_bgp_unique_rid_multi_bgp_nbrs_p0():
    """
    TC: 3
    3. Verify two different eBGP sessions initiated with same router ID

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
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r4": {"bgp": {"router_id": "10.10.10.10"}},
        "r5": {"bgp": {"router_id": "10.10.10.10"}},
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
                    "address_family": {
                        "ipv4": {
                            "unicast": {"neighbor": {rtr: {"dest_link": {"lo": {}}}}}
                        }
                    }
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


def test_bgp_unique_rid_chaos1_p2():
    """
    TC: 4
    4. Chaos - Verify bgp unique rid functionality in chaos scenarios.

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

    step("Configure the same router id between R3, R4 and R5 (10.10.10.10)")
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r4": {"bgp": {"router_id": "10.10.10.10"}},
        "r5": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify neighbours are in ESTAB state.")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify eBGP session when same router ID is configured and bgpd process is restarted"
    )

    # restart bgpd router and verify
    kill_router_daemons(tgen, "r3", ["bgpd"])
    start_router_daemons(tgen, "r3", ["bgpd"])

    step(
        "The session should be established between R3 & R4. "
        "Once after restart bgp, neighbor should come back up ."
    )

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Verify eBGP session when same router ID is configured and neighbor shutdown is issued and again no shutdown."
    )

    input_dict = {
        "r3": {
            "bgp": {
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {"shutdown": True},
                                        "r3-link2": {"shutdown": True},
                                        "r3-link3": {"shutdown": True},
                                        "r3-link4": {"shutdown": True},
                                        "r3-link5": {"shutdown": True},
                                        "r3-link6": {"shutdown": True},
                                        "r3-link7": {"shutdown": True},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {"shutdown": True}}},
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {"shutdown": True},
                                        "r3-link2": {"shutdown": True},
                                        "r3-link3": {"shutdown": True},
                                        "r3-link4": {"shutdown": True},
                                        "r3-link5": {"shutdown": True},
                                        "r3-link6": {"shutdown": True},
                                        "r3-link7": {"shutdown": True},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {"shutdown": True}}},
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r3": {
            "bgp": {
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {"shutdown": False},
                                        "r3-link2": {"shutdown": False},
                                        "r3-link3": {"shutdown": False},
                                        "r3-link4": {"shutdown": False},
                                        "r3-link5": {"shutdown": False},
                                        "r3-link6": {"shutdown": False},
                                        "r3-link7": {"shutdown": False},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {"shutdown": False}}},
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {"shutdown": False},
                                        "r3-link2": {"shutdown": False},
                                        "r3-link3": {"shutdown": False},
                                        "r3-link4": {"shutdown": False},
                                        "r3-link5": {"shutdown": False},
                                        "r3-link6": {"shutdown": False},
                                        "r3-link7": {"shutdown": False},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {"shutdown": False}}},
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "The session should be established between R3 & R4. "
        "Once after restart bgp, neighbor should come back up ."
    )

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Verify eBGP session when same router ID is configured and neighbor config is deleted & reconfigured."
    )

    input_dict = {
        "r3": {
            "bgp": {
                "local_as": "100",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {},
                                        "r3-link2": {},
                                        "r3-link3": {},
                                        "r3-link4": {},
                                        "r3-link5": {},
                                        "r3-link6": {},
                                        "r3-link7": {},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {}}},
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3-link1": {},
                                        "r3-link2": {},
                                        "r3-link3": {},
                                        "r3-link4": {},
                                        "r3-link5": {},
                                        "r3-link6": {},
                                        "r3-link7": {},
                                    }
                                },
                                "r5": {"dest_link": {"r3": {}}},
                            }
                        }
                    },
                },
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "The session should be established between R3 & R4. "
        "Once after restart bgp, neighbor should come back up ."
    )

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Verify eBGP session when same router ID is configured and FRR router is restarted."
    )
    stop_router(tgen, "r3")
    start_router(tgen, "r3")

    step(
        "The session should be established between R3 & R4. "
        "Once after restart bgp, neighbor should come back up ."
    )

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Verify eBGP session when same router ID is configured and zebra process is restarted"
    )

    kill_router_daemons(tgen, "r3", ["zebra"])
    start_router_daemons(tgen, "r3", ["zebra"])

    step(
        "The session should be established between R3 & R4. "
        "Once after restart bgp, neighbor should come back up ."
    )

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    write_test_footer(tc_name)


def test_bgp_unique_rid_chaos3_p2():
    """
    TC: 4
    4. Chaos - Verify bgp unique rid functionality when router reboots with same loopback id.

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

    global topo
    topo1 = deepcopy(topo)

    for rtr in topo["routers"].keys():
        topo1["routers"][rtr]["links"]["lo"]["ipv4"] = "192.168.1.1/32"

    topo1["routers"]["r3"]["links"]["lo"]["ipv4"] = "192.168.1.3/32"
    build_config_from_json(tgen, topo1, save_bkup=False)

    step("verify bgp convergence before starting test case")

    bgp_convergence = verify_bgp_convergence(tgen, topo1)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step(
        "Configure loopback on R1 to R5 with IP address 1.1.1.1 on all the routers. Change neighborship on all the routers using loopback neighborship ids."
    )
    for rtr in ["r1", "r2", "r4", "r5"]:
        configure_bgp_on_rtr = {
            "r3": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {"neighbor": {rtr: {"dest_link": {"lo": {}}}}}
                        }
                    }
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

    step("Reboot the router (restart frr) or using watch frr.")
    stop_router(tgen, "r3")
    start_router(tgen, "r3")

    step("Neighbors between R3, R4 and R3 to R5 should be in ESTB state.")
    bgp_convergence = verify_bgp_convergence(tgen, topo1, dut="r3")
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Clear bgp process.")
    clear_bgp_and_verify(tgen, topo, "r3")

    step("Neighbors between R3, R4 and R3 to R5 should be in ESTB state.")
    bgp_convergence = verify_bgp_convergence(tgen, topo1, dut="r3")
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    write_test_footer(tc_name)


def test_bgp_unique_rid_chaos4_p2():
    """
    TC: 6
    6. Chaos - Verify bgp unique rid functionality when router reboots without any ip addresses.

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

    reset_config_on_routers(tgen)

    global topo
    topo1 = deepcopy(topo)
    topo2 = deepcopy(topo)

    step(
        "Configure base config as per the topology without loopback as well as Ip address on any of the interface."
    )
    for rtr in topo["routers"].keys():
        for intf in topo["routers"][rtr]["links"].keys():
            topo1["routers"][rtr]["links"][intf].pop("ipv4")
            topo1["routers"][rtr]["links"][intf].pop("ipv6")

    build_config_from_json(tgen, topo1, save_bkup=False)

    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Configure the ip addresses on the physical interfaces")
    build_config_from_json(tgen, topo2, save_bkup=False)

    step("All the neighbors should be in ESTAB state.")
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Configure loopback addresses with higher IP address ")
    build_config_from_json(tgen, topo, save_bkup=False)

    step("All the neighbors should be in ESTAB state.")
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    step("Reboot the router (restart frr) or using watch frr.")
    stop_router(tgen, "r3")
    start_router(tgen, "r3")

    step("Neighbors between R3, R4 and R3 to R5 should be in ESTB state.")
    bgp_convergence = verify_bgp_convergence(tgen, topo, dut="r3")
    assert bgp_convergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, bgp_convergence
    )

    write_test_footer(tc_name)


def test_bgp_unique_rid_chaos2_p2():
    """
    TC: 8
    8. Chaos - Verify bgp unique rid functionality when ospf and bgp share the same router ids.

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
    step("Redistribute routes between bgp and ospf.")
    reset_config_on_routers(tgen)

    step(
        "Base config should be up, verify using BGP convergence on all \
    the routers for IPv4 and IPv6 nbrs"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut="r3")
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step(
        "Configure ospf between R3 and R4 with same router ids in both ospf and bgp 10.10.10.10 on R3 BGP and OSPF, and 10.10.10.10 in R4 BGP and 11.11.11.11 in R4 OSPF."
    )
    input_dict = {
        "r3": {"bgp": {"router_id": "10.10.10.10"}},
        "r4": {"bgp": {"router_id": "10.10.10.10"}},
        "r5": {"bgp": {"router_id": "10.10.10.10"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "The session should be established between R3 & R4 between BGP process and neighborship should be full between OSPF too."
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut="r3")
    assert ospf_covergence is True, "Testcase :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    step("All the routes should be calculated and installed.")
    # Verifying RIB routes
    protocol = "bgp"
    input_dict = topo["routers"]
    verify_rib_rtes = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {"network": NETWORK["ipv4"], "next_hop": "Null0"},
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"],
                        "next_hop": "Null0",
                    }
                ]
            }
        },
    }
    dut = "r3"
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_rib_rtes,
            protocol=protocol,
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Clear ospf process.")
    clear_ospf(tgen, "r3")

    step("All the routes should be calculated and installed.")
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_rib_rtes,
            protocol=protocol,
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Clear bgp process.")
    clear_bgp_and_verify(tgen, topo, "r3")

    step("All the routes should be calculated and installed.")
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_rib_rtes,
            protocol=protocol,
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step(
        "Configure ospf between R3 and R5.  Configure static routes in R5 and redistribute static routes in ospf on R5."
    )
    # Covered as base config.

    step("Verify routes are installed in R3 and R4 route tables.")
    dut = "r4"
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(
            tgen,
            addr_type,
            dut,
            verify_rib_rtes,
            protocol=protocol,
        )
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
