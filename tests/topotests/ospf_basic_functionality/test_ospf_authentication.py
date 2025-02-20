#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
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
from lib.topotest import frr_unicode

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
from lib.topojson import build_config_from_json
from lib.ospf import verify_ospf_neighbor, config_ospf_interface, clear_ospf
from ipaddress import IPv4Address

pytestmark = [pytest.mark.ospfd]


# Global variables
topo = None
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
1. Verify ospf authentication with Simple password authentication.
2. Verify ospf authentication with MD5 authentication.
3. Verify ospf authentication with MD5 keychain authentication.
4. Verify ospf authentication with SHA256 keychain authentication.
5. Verify ospf authentication with different authentication methods.

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
    json_file = "{}/ospf_authentication.json".format(CWD)
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


# ##################################
# Test cases start here.
# ##################################


def test_ospf_authentication_simple_pass_tc28_p1(request):
    """
    OSPF Authentication - Verify ospf authentication with Simple
    password authentication.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf with on R1 and R2, enable ospf on R1 interface"
        "connected to R2 with simple password authentication  using  ip ospf "
        "authentication  Simple password cmd."
    )

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("clear ip ospf after configuring the authentication.")
    clear_ospf(tgen, "r1")

    step("Verify that the neighbour is not FULL between R1 and R2.")
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "On R2 enable ospf on interface with simple password authentication "
        "using ip ospf authentication  Simple password cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2  "
        "using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "Disable simple password authentication on R2  using no ip ospf "
        "authentication Simple password cmd."
    )
    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": True,
                        "authentication-key": "ospf",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 neighbour is deleted for R2 after dead interval expiry")
    # wait till the dead time expiry
    sleep(6)
    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Again On R2 enable ospf on interface with  Simple password auth")
    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using"
        " show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbour is not FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change Ip address on R1 and R2")

    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"]
    topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)

    reset_config_on_routers(tgen, routerName="r1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    # clear ip ospf after configuring the authentication.
    clear_ospf(tgen, "r1")

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 with new "
        "ip address using show ip ospf "
    )

    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_authentication_md5_tc29_p1(request):
    """
    OSPF Authentication - Verify ospf authentication with MD5 authentication.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf with on R1 and R2, enable ospf on R1 interface "
        "connected to R2 with message-digest authentication using  ip "
        "ospf authentication  message-digest cmd."
    )

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbour is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=6
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "On R2 enable ospf on interface with message-digest authentication"
        "  using  ip ospf authentication  message-digest password cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2  "
        "using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "Disable message-digest authentication on R2  using no ip ospf "
        "authentication  message-digest password cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Again On R2 enable ospf on interface with  message-digest auth")
    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using"
        " show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbour is not FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change Ip address on R1 and R2")

    topo_modify_change_ip = deepcopy(topo)

    intf_ip = topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"]

    topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)

    reset_config_on_routers(tgen, routerName="r1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)
    clear_ospf(tgen, "r1")
    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 with new "
        "ip address using show ip ospf "
    )

    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_authentication_md5_keychain_tc30_p1(request):
    """
    OSPF Authentication - Verify ospf authentication with MD5 authentication.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf with on R1 and R2, enable ospf on R1 interface "
        "connected to R2 with message-digest authentication using  ip "
        "ospf authentication key-chain cmd."
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm md5"""
    )

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbour is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=6
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "On R2 enable ospf on interface with message-digest authentication"
        "  using  ip ospf authentication  message-digest password cmd."
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm md5"""
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2  "
        "using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "Disable message-digest authentication on R2  using no ip ospf "
        "authentication  key-chain cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Again On R2 enable ospf on interface with key-chain auth")
    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using"
        " show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbour is not FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change Ip address on R1 and R2")

    topo_modify_change_ip = deepcopy(topo)

    intf_ip = topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"]

    topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)

    reset_config_on_routers(tgen, routerName="r1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)
    clear_ospf(tgen, "r1")
    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm md5"""
    )
    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 with new "
        "ip address using show ip ospf "
    )

    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_authentication_sha256_keychain_tc32_p1(request):
    """
    OSPF Authentication - Verify ospf authentication with MD5 authentication.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf with on R1 and R2, enable ospf on R1 interface "
        "connected to R2 with message-digest authentication using  ip "
        "ospf authentication key-chain cmd."
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm hmac-sha-256"""
    )

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that the neighbour is not FULL between R1 and R2.")
    # wait for dead time expiry.
    sleep(6)
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=6
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "On R2 enable ospf on interface with message-digest authentication"
        "  using  ip ospf authentication  message-digest password cmd."
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm hmac-sha-256"""
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2  "
        "using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "Disable message-digest authentication on R2  using no ip ospf "
        "authentication  key-chain cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify on R1 ,nbr is deleted for R2 after dead interval expiry")
    #  wait till the dead timer expiry
    sleep(6)
    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Again On R2 enable ospf on interface with key-chain auth")
    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using"
        " show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Shut no shut interface on R1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "r2"
    step(
        "Verify that the neighbour is not FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut, expected=False)
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    dut = "r1"
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using "
        "show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change Ip address on R1 and R2")

    topo_modify_change_ip = deepcopy(topo)

    intf_ip = topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"]

    topo_modify_change_ip["routers"]["r1"]["links"]["r2"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)

    reset_config_on_routers(tgen, routerName="r1")
    dut = "r1"
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)
    clear_ospf(tgen, "r1")
    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm hmac-sha-256"""
    )
    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 with new "
        "ip address using show ip ospf "
    )

    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_authentication_different_auths_tc35_p1(request):
    """
    OSPF Authentication - Verify ospf authentication with different
    authentication methods.

    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo
    step("Bring up the base config.")
    reset_config_on_routers(tgen)
    step(
        "Configure ospf with on R1 and R2, enable ospf on R1 interface "
        "connected to R2 with message-digest authentication using  ip "
        "ospf authentication  message-digest cmd."
    )

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # wait for dead timer expiry
    sleep(6)
    step("Verify that the neighbour is not FULL between R1 and R2.")
    dut = "r1"
    ospf_covergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_covergence is not True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(
        "On R2 enable ospf on interface with message-digest authentication"
        "  using  ip ospf authentication  message-digest password cmd."
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2  "
        "using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(" Delete the configured password on both the routers.")

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospf",
                        "message-digest-key": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the deletion is successful and  neighbour is FULL"
        " between R1 and R2 using show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change the authentication type to simple password.")
    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {"ospf": {"authentication": True, "authentication-key": "ospf"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the deletion is successful and  neighbour is"
        " FULL between R1 and R2 using show ip "
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change the password in simple password.")

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {"ospf": {"authentication": True, "authentication-key": "OSPFv4"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {"ospf": {"authentication": True, "authentication-key": "OSPFv4"}}
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the deletion is successful and  neighbour is"
        " FULL between R1 and R2 using show ip "
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Delete the password authentication on the interface ")

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": True,
                        "authentication-key": "OSPFv4",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": True,
                        "authentication-key": "OSPFv4",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the deletion is successful and  neighbour is"
        " FULL between R1 and R2 using show ip "
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Enable SHA-256 authentication on the interface")

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm hmac-sha-256"""
    )

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string ospf
               cryptographic-algorithm hmac-sha-256"""
    )

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "key-chain",
                        "keychain": "auth",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that the neighbour is FULL between R1 and R2 using"
        " show ip ospf neighbor cmd."
    )

    dut = "r2"
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("Change the SHA-256 authentication password")

    router1.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string OSPFv4
               cryptographic-algorithm hmac-sha-512"""
    )

    router2.vtysh_cmd(
        """configure terminal
           key chain auth
             key 10
               key-string OSPFv4
               cryptographic-algorithm hmac-sha-512"""
    )
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
