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
from time import sleep
from copy import deepcopy
import json
from lib.topotest import frr_unicode

pytestmark = pytest.mark.ospf6d

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

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
    shutdown_bringup_interface,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json
from lib.ospf import verify_ospf6_neighbor, config_ospf6_interface, clear_ospf
from ipaddress import IPv4Address

# Global variables
topo = None
# Reading the data from JSON File for topology creation
jsonFile = "{}/ospfv3_authentication.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)
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
1.  OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 manual key configuration.
2.  OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 manual key configuration.
3.  OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 keychain configuration.
4.  OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 keychain configuration.

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
    json_file = "{}/ospfv3_single_area.json".format(CWD)
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

    ospf6_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf6_covergence is True, "setup_module :Failed \n Error:  {}".format(
        ospf6_covergence
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


def test_ospf6_auth_trailer_tc1_md5(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 manual key configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Disable authentication on R2 ")

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=5
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Again On R2 enable ospf6 on interface with  message-digest auth")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using"
        " show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbor is not FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc2_sha256(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 manual key configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Disable authentication on R2 ")

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=5
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Again On R2 enable ospf6 on interface with  message-digest auth")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using"
        " show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbor is not FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Change the key ID on R2 to not match R1")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "30",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on R1 that R2 nbr is deleted due to key-id mismatch "
        "after dead interval expiry"
    )
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=5
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Correct the key ID on R2 so that it matches R1")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc3_keychain_md5(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 keychain configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm md5"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm md5"""
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Disable authentication on R2 ")

    r2_ospf6_auth = {
        "r2": {"links": {"r1": {"ospf6": {"keychain": "auth", "del_action": True}}}}
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=5
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Again On R2 enable ospf6 on interface with  message-digest auth")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using"
        " show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbor is not FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc4_keychain_sha256(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 keychain configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm hmac-sha-256"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm hmac-sha-256"""
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Disable authentication on R2 ")

    r2_ospf6_auth = {
        "r2": {"links": {"r1": {"ospf6": {"keychain": "auth", "del_action": True}}}}
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=5
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Again On R2 enable ospf6 on interface with  message-digest auth")
    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using"
        " show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbor is not FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbor is FULL between R1 and R2 using "
        "show ip ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc5_md5_keymissmatch(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 manual key configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer wrong key"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6-missmatch",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is not FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    step("Verify that the neighbor is FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer correct key"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "md5",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc6_sha256_mismatch(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 manual key configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 with on R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer wrong key"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6-missmatch",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 with on R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer wrong key"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "hash-algo": "hmac-sha-256",
                        "key": "ospf6",
                        "key-id": "10",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc7_keychain_md5_missmatch(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using MD5 keychain configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm md5"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm md5"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth-missmatch
             key 10
               key-string ospf6-missmatch
               cryptographic-algorithm md5"""
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer with wrong keychain"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth-missmatch",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer with correct keychain"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc8_keychain_sha256_missmatch(request):
    """
    OSPFv3 Authentication Trailer - Verify ospfv3 authentication trailer
    using HMAC-SHA-256 keychain configuration.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm hmac-sha-256"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf6
               cryptographic-algorithm hmac-sha-256"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth-missmatch
             key 10
               key-string ospf6-missmatch
               cryptographic-algorithm hmac-sha-256"""
    )

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer wrong keychain"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth-missmatch",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer correct keychain"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc9_keychain_not_configured(request):
    """
    OSPFv3 Neighborship without Authentication Trailer -
    Verify ospfv3 neighborship when no authentication trailer is configured.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf6 between R1 and R2, enable ospf6 auth on R1 interface "
        "connected to R2 with auth trailer"
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    r1_ospf6_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    step(
        "Configure ospf6 between R1 and R2, enable ospf6 on R2 interface "
        "connected to R1 with auth trailer non existing keychain"
    )

    r2_ospf6_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf6": {
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf6_interface(tgen, topo, r2_ospf6_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbor is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=3
    )
    assert ospf6_covergence is not True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


def test_ospf6_auth_trailer_tc10_no_auth_trailer(request):
    """
    OSPFv3 Neighborship without Authentication Trailer -
    Verify ospfv3 neighborship when no authentication trailer is configured.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    step(
        "Verify that the neighbor is FULL between R1 and R2  "
        "using show ipv6 ospf6 neighbor cmd."
    )

    dut = "r2"
    ospf6_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf6_covergence is True, "Testcase {} :Failed \n Error:  {}".format(
        tc_name, ospf6_covergence
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
