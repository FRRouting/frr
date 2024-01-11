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
from copy import deepcopy
from ipaddress import IPv4Address
from lib.topotest import frr_unicode

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
import ipaddress

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    create_interfaces_cfg,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf_neighbor,
    config_ospf_interface,
    clear_ospf,
    verify_ospf_rib,
    verify_ospf_interface,
)

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]
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
1. OSPF IFSM -Verify state change events on p2p network.
2. OSPF Timers - Verify OSPF interface timer hello interval functionality
3. OSPF Timers - Verify OSPF interface timer dead interval functionality
4. Verify ospf show commands with json output.
5. Verify NFSM events when ospf nbr changes with different MTU values.
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
    json_file = "{}/ospf_single_area.json".format(CWD)
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


def test_ospf_p2p_tc3_p0(request):
    """OSPF IFSM -Verify state change events on p2p network."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)
    step(
        "Verify that OSPF is subscribed to multi cast services "
        "(All SPF, all DR Routers)."
    )
    step("Verify that interface is enabled in ospf.")
    step("Verify that config is successful.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r3": {"ospf": {"mcastMemberOspfAllRouters": True, "ospfEnabled": True}}
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo["routers"]["r0"]["links"]["r3"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ip on the R0 interface")

    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"]
    topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "ospf": {
                        "ipAddress": topo_modify_change_ip["routers"]["r0"]["links"][
                            "r3"
                        ]["ipv4"].split("/")[0],
                        "ipAddressPrefixlen": int(
                            topo_modify_change_ip["routers"]["r0"]["links"]["r3"][
                                "ipv4"
                            ].split("/")[1]
                        ),
                    }
                }
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Modify the mask on the R0 interface")
    ip_addr = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"]
    mask = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"]
    step("Delete the ip address")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": ip_addr,
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ip on the R0 interface")

    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"]
    topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(int(intf_ip.split("/")[1]) + 1)

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "ospf": {
                        "ipAddress": topo_modify_change_ip["routers"]["r0"]["links"][
                            "r3"
                        ]["ipv4"].split("/")[0],
                        "ipAddressPrefixlen": int(
                            topo_modify_change_ip["routers"]["r0"]["links"]["r3"][
                                "ipv4"
                            ].split("/")[1]
                        ),
                    }
                }
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": topo_modify_change_ip["routers"]["r0"]["links"]["r3"][
                        "ipv4"
                    ],
                    "interface": topo_modify_change_ip["routers"]["r0"]["links"]["r3"][
                        "interface"
                    ],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    build_config_from_json(tgen, topo, save_bkup=False)

    step("Change the area id on the interface")
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf": {"area": "0.0.0.0"},
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
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf": {"area": "0.0.0.1"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {"links": {"r3": {"ospf": {"area": "0.0.0.1", "ospfEnabled": True}}}}
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf": {"area": "0.0.0.1"},
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
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf": {"area": "0.0.0.0"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call verify whether BGP is converged
    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_hello_tc10_p0(request):
    """
    OSPF timers.

    Verify OSPF interface timer hello interval functionality
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

    step("modify hello timer from default value to some other value on r1")

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"hello_interval": 11, "dead_interval": 12},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "verify that new timer value is configured and applied using "
        "the show ip ospf interface command."
    )
    dut = "r1"
    input_dict = {
        "r1": {
            "links": {"r0": {"ospf": {"timerMsecs": 11 * 1000, "timerDeadSecs": 12}}}
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("modify hello timer from default value to r1 hello timer on r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"hello_interval": 11, "dead_interval": 12},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {"r1": {"ospf": {"timerMsecs": 11 * 1000, "timerDeadSecs": 12}}}
        }
    }
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("reconfigure the default hello timer value to default on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {"r1": {"ospf": {"timerMsecs": 10 * 1000, "timerDeadSecs": 40}}}
        }
    }
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("reconfigure the default hello timer value to default on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {"r1": {"ospf": {"timerMsecs": 10 * 1000, "timerDeadSecs": 40}}}
        }
    }
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("configure hello timer = 1 on r1 and r2")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"hello_interval": 1, "dead_interval": 4},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"hello_interval": 1, "dead_interval": 4},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {"links": {"r1": {"ospf": {"timerMsecs": 1 * 1000, "timerDeadSecs": 4}}}}
    }
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


def test_ospf_show_p1(request):
    """Verify ospf show commands with json output."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step(" Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf_neighbor(tgen, topo)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )
    dut = "r1"
    input_dict = {
        "r1": {
            "links": {
                "r0": {
                    "ospf": {
                        "ifUp": True,
                        "ifFlags": "<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                        "ospfEnabled": True,
                        "ipAddressPrefixlen": 24,
                        "ospfIfType": "Broadcast",
                        "area": "0.0.0.0",
                        "networkType": "BROADCAST",
                        "cost": 10,
                        "transmitDelaySecs": 1,
                        "state": "DR",
                        "priority": 1,
                        "mcastMemberOspfAllRouters": True,
                        "timerMsecs": 1000,
                        "timerDeadSecs": 4,
                        "timerWaitSecs": 4,
                        "timerRetransmitSecs": 5,
                        "nbrCount": 1,
                        "nbrAdjacentCount": 1,
                    }
                }
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # show ip ospf route
    ip = topo["routers"]["r0"]["links"]["r3"]["ipv4"]
    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv4"].split("/")[0]
    input_dict = {
        "r1": {"static_routes": [{"network": ip_net, "no_of_ip": 1, "routeType": "N"}]}
    }

    dut = "r1"
    result = verify_ospf_rib(tgen, dut, input_dict, next_hop=nh)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_dead_tc11_p0(request):
    """
    OSPF timers.

    Verify OSPF interface timer dead interval functionality
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

    step("modify dead interval from default value to some other value on r1")

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"hello_interval": 12, "dead_interval": 48},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "verify that new timer value is configured and applied using "
        "the show ip ospf interface command."
    )
    dut = "r1"
    input_dict = {"r1": {"links": {"r0": {"ospf": {"timerDeadSecs": 48}}}}}
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("modify dead interval from default value to r1 dead interval timer on r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"dead_interval": 48, "hello_interval": 12},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {"r0": {"links": {"r1": {"ospf": {"timerDeadSecs": 48}}}}}
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step("reconfigure the default dead interval timer value to  default on r1 and r2")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {"r0": {"links": {"r1": {"ospf": {"timerDeadSecs": 40}}}}}
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(" Configure dead timer = 65535 on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"dead_interval": 65535},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"dead_interval": 65535},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {"r0": {"links": {"r1": {"ospf": {"timerDeadSecs": 65535}}}}}
    dut = "r0"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error  {}".format(
        ospf_covergence
    )

    step(" Try configuring timer values outside range for example 65536")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf": {"dead_interval": 65536},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step("Unconfigure the dead timer from the interface from r1 and r2.")

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf": {"dead_interval": 65535},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that timer value is deleted from intf &  set to default value 40 sec.")
    input_dict = {"r1": {"links": {"r0": {"ospf": {"timerDeadSecs": 40}}}}}
    dut = "r1"
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_tc4_mtu_ignore_p0(request):
    """
    OSPF NFSM - MTU change

    Verify NFSM events when ospf nbr changes with different MTU values
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step(" Bring up the base config as per the topology")
    step("Configure OSPF on all the routers of the topology.")
    step("Verify that OSPF neighbors are FULL.")
    reset_config_on_routers(tgen)
    result = verify_ospf_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Modify the MTU to non default Value on R0 to R1 interface. "
        "Reset ospf neighbors on R0."
    )

    rtr0 = tgen.routers()["r0"]
    rtr1 = tgen.routers()["r1"]

    r0_r1_intf = topo["routers"]["r0"]["links"]["r1"]["interface"]
    r1_r0_intf = topo["routers"]["r1"]["links"]["r0"]["interface"]

    rtr0.run("ip link set {} mtu 1200".format(r0_r1_intf))

    clear_ospf(tgen, "r0")

    step("Verify that OSPF neighborship between R0 and R1 is stuck in Exstart  State.")
    result = verify_ospf_neighbor(tgen, topo, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n OSPF nbrs are Full "
        "instead of Exstart. Error: {}".format(tc_name, result)
    )

    step("Verify that configured MTU value is updated in the show ip  ospf interface.")

    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf": {"mtuBytes": 1200}}}}}
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Modify the MTU to non default Value on R0 to R1 interface. "
        "Reset ospf neighbors on R0."
    )
    rtr0.run("ip link set {} mtu 1500".format(r0_r1_intf))

    clear_ospf(tgen, "r0")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure mtu ignore and change the value of the mtu to non default"
        " on R0 to R1 interface. Reset ospf neighbors on R0."
    )
    r0_ospf_mtu = {"r0": {"links": {"r1": {"ospf": {"mtu_ignore": True}}}}}
    result = config_ospf_interface(tgen, topo, r0_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf": {"mtuMismatchDetect": True}}}}}
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    r1_ospf_mtu = {"r1": {"links": {"r0": {"ospf": {"mtu_ignore": True}}}}}
    result = config_ospf_interface(tgen, topo, r1_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    rtr0.run("ip link set {} mtu 1200".format(r0_r1_intf))

    clear_ospf(tgen, "r0")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Unconfigure mtu-ignore command from the interface. "
        "Reset ospf neighbors on R0."
    )

    r1_ospf_mtu = {
        "r1": {"links": {"r0": {"ospf": {"mtu_ignore": True, "del_action": True}}}}
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    clear_ospf(tgen, "r0")

    step("Verify that OSPF neighborship between R0 and R1 is stuck in Exstart  State.")
    result = verify_ospf_neighbor(tgen, topo, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n OSPF nbrs are Full "
        "instead of Exstart. Error: {}".format(tc_name, result)
    )

    step("Modify the MTU to again default valaue on R0 to R1 interface.")

    rtr0.run("ip link set {} mtu 1500".format(r0_r1_intf))

    clear_ospf(tgen, "r0")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure ospf interface with jumbo MTU (9216). Reset ospf neighbors on R0.")

    rtr0.run("ip link set {} mtu 9216".format(r0_r1_intf))
    rtr1.run("ip link set {} mtu 9216".format(r1_r0_intf))

    clear_ospf(tgen, "r0")
    clear_ospf(tgen, "r1")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that jumbo MTU is updated in the show ip ospf interface.")
    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf": {"mtuBytes": 9216}}}}}
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
