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
import ipaddress

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
    create_interfaces_cfg,
    create_debug_log_config,
    apply_raw_config,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

from lib.ospf import (
    verify_ospf6_neighbor,
    clear_ospf,
    verify_ospf6_interface,
    create_router_ospf,
    config_ospf6_interface,
    verify_ospf6_rib,
)

from ipaddress import IPv6Address

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

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "setup_module :Failed \n Error:  {}".format(
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


def test_ospfv3_p2p_tc3_p0(request):
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
    input_dict = {"r0": {"links": {"r3": {"ospf6": {}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete the ip address")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo["routers"]["r0"]["links"]["r3"]["ipv6"],
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
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"]
    topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"] = str(
        IPv6Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "ospf6": {
                        "internetAddress": [
                            {
                                "type": "inet6",
                                "address": topo_modify_change_ip["routers"]["r0"][
                                    "links"
                                ]["r3"]["ipv6"].split("/")[0],
                            }
                        ],
                    }
                }
            }
        }
    }
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Modify the mask on the R0 interface")
    ip_addr = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"]
    mask = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"]
    step("Delete the ip address")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": ip_addr,
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
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"]
    topo_modify_change_ip["routers"]["r0"]["links"]["r3"]["ipv6"] = str(
        IPv6Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(int(intf_ip.split("/")[1]) + 1)

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "ospf6": {
                        "internetAddress": [
                            {
                                "type": "inet6",
                                "address": topo_modify_change_ip["routers"]["r0"][
                                    "links"
                                ]["r3"]["ipv6"].split("/")[0],
                            }
                        ],
                    }
                }
            }
        }
    }
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv6": topo_modify_change_ip["routers"]["r0"]["links"]["r3"][
                        "ipv6"
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
                    "ospf6": {"area": "0.0.0.0"},
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
                    "ospf6": {"area": "0.0.0.1"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {"r0": {"links": {"r3": {"ospf6": {}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf6": {"area": "0.0.0.1"},
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
                    "ospf6": {"area": "0.0.0.0"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {"r0": {"links": {"r3": {"ospf6": {}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify the all neighbors are up after clearing the process.")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_hello_tc10_p0(request):
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
                    "ospf6": {"hello_interval": 11, "dead_interval": 12},
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
            "links": {
                "r0": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 11,
                        "timerIntervalsConfigDead": 12,
                    }
                }
            }
        }
    }
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("modify hello timer from default value to r1 hello timer on r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 11, "dead_interval": 12},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 11,
                        "timerIntervalsConfigDead": 12,
                    }
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step("reconfigure the default hello timer value to default on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 10, "dead_interval": 40},
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
                    "ospf6": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 10,
                        "timerIntervalsConfigDead": 40,
                    }
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step("reconfigure the default hello timer value to default on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 10, "dead_interval": 40},
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
                    "ospf6": {"hello_interval": 10, "dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 10,
                        "timerIntervalsConfigDead": 40,
                    }
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step("configure hello timer = 1 on r1 and r2")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 1, "dead_interval": 4},
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
                    "ospf6": {"hello_interval": 1, "dead_interval": 4},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 1,
                        "timerIntervalsConfigDead": 4,
                    }
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase Failed \n Error:  {}".format(
        ospf_covergence
    )

    step(" Configure hello timer = 65535")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 65535, "dead_interval": 4},
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
                    "ospf6": {"hello_interval": 65535, "dead_interval": 4},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf6": {
                        "timerIntervalsConfigHello": 65535,
                        "timerIntervalsConfigDead": 4,
                    }
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(" Try configuring timer values outside range for example 65536")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"hello_interval": 65536, "dead_interval": 4},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Create interface failed. Error: {}".format(
        tc_name, result
    )

    step("Unconfigure the hello timer from the interface from r1 and r2.")

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf6": {"hello_interval": 65535},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that timer value is deleted from intf &  set to default value 40 sec.")
    input_dict = {"r1": {"links": {"r0": {"ospf6": {"timerIntervalsConfigHello": 10}}}}}
    dut = "r1"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_dead_tc11_p0(request):
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
                    "ospf6": {"hello_interval": 12, "dead_interval": 48},
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
    input_dict = {"r1": {"links": {"r0": {"ospf6": {"timerIntervalsConfigDead": 48}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("modify dead interval from default value to r1 dead interval timer on r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"dead_interval": 48, "hello_interval": 12},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {"r0": {"links": {"r1": {"ospf6": {"timerIntervalsConfigDead": 48}}}}}
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, ospf_covergence
    )

    step("remove ospf on R0")
    ospf_del = {"r0": {"ospf6": {"delete": True}}}
    result = create_router_ospf(tgen, topo, ospf_del)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    # reconfiguring deleted ospf process by resetting the configs.
    reset_config_on_routers(tgen)

    step("reconfigure the default dead interval timer value to  default on r1 and r2")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"dead_interval": 40},
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
                    "ospf6": {"dead_interval": 40},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {"r0": {"links": {"r1": {"ospf6": {"timerIntervalsConfigDead": 40}}}}}
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, ospf_covergence
    )

    step(" Configure dead timer = 65535 on r1 and r2")

    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"dead_interval": 65535},
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
                    "ospf6": {"dead_interval": 65535},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that new timer value is configured.")
    input_dict = {
        "r0": {"links": {"r1": {"ospf6": {"timerIntervalsConfigDead": 65535}}}}
    }
    dut = "r0"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("verify that ospf neighbours are  full")
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, dut=dut)
    assert ospf_covergence is True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, ospf_covergence
    )

    step(" Try configuring timer values outside range for example 65536")
    topo1 = {
        "r0": {
            "links": {
                "r1": {
                    "interface": topo["routers"]["r0"]["links"]["r1"]["interface"],
                    "ospf6": {"dead_interval": 65536},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert (
        result is not True
    ), "Testcase {} : Failed \n Create interface config failed. Error: {}".format(
        tc_name, result
    )

    step("Unconfigure the dead timer from the interface from r1 and r2.")

    topo1 = {
        "r1": {
            "links": {
                "r0": {
                    "interface": topo["routers"]["r1"]["links"]["r0"]["interface"],
                    "ospf6": {"dead_interval": 65535},
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that timer value is deleted from intf &  set to default value 40 sec.")
    input_dict = {"r1": {"links": {"r0": {"ospf6": {"timerIntervalsConfigDead": 40}}}}}
    dut = "r1"
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_tc4_mtu_ignore_p0(request):
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

    step(
        "Modify the MTU to non default Value on R0 to R1 interface. "
        "Reset ospf neighbors on R0."
    )

    rtr0 = tgen.routers()["r0"]
    rtr1 = tgen.routers()["r1"]

    r0_r1_intf = topo["routers"]["r0"]["links"]["r1"]["interface"]
    r1_r0_intf = topo["routers"]["r1"]["links"]["r0"]["interface"]

    rtr0.run("ifconfig {} mtu 1400".format(r0_r1_intf))

    clear_ospf(tgen, "r0", ospf="ospf6")
    clear_ospf(tgen, "r1", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 is stuck in Exstart  State.")
    result = verify_ospf6_neighbor(tgen, topo, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n OSPF nbrs are Full "
        "instead of Exstart. Error: {}".format(tc_name, result)
    )

    step("Verify that configured MTU value is updated in the show ip  ospf interface.")

    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf6": {"interfaceMtu": 1400}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Modify the MTU to non default Value on R0 to R1 interface. "
        "Reset ospf neighbors on R0."
    )
    rtr0.run("ifconfig {} mtu 1500".format(r0_r1_intf))

    clear_ospf(tgen, "r0", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure mtu ignore and change the value of the mtu to non default"
        " on R0 to R1 interface. Reset ospf neighbors on R0."
    )
    r0_ospf_mtu = {"r0": {"links": {"r1": {"ospf6": {"mtu_ignore": True}}}}}
    result = config_ospf6_interface(tgen, topo, r0_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf6": {"mtuMismatchDetection": True}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    r1_ospf_mtu = {"r1": {"links": {"r0": {"ospf6": {"mtu_ignore": True}}}}}
    result = config_ospf6_interface(tgen, topo, r1_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    rtr0.run("ifconfig {} mtu 1400".format(r0_r1_intf))

    clear_ospf(tgen, "r0", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Unconfigure mtu-ignore command from the interface. "
        "Reset ospf neighbors on R0."
    )

    r1_ospf_mtu = {
        "r1": {"links": {"r0": {"ospf6": {"mtu_ignore": True, "delete": True}}}}
    }
    result = config_ospf6_interface(tgen, topo, r1_ospf_mtu)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    clear_ospf(tgen, "r0", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 is stuck in Exstart  State.")
    result = verify_ospf6_neighbor(tgen, topo, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n OSPF nbrs are Full "
        "instead of Exstart. Error: {}".format(tc_name, result)
    )

    step("Modify the MTU to again default valaue on R0 to R1 interface.")

    rtr0.run("ifconfig {} mtu 1500".format(r0_r1_intf))

    clear_ospf(tgen, "r0", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure ospf interface with jumbo MTU (9216). Reset ospf neighbors on R0.")

    rtr0.run("ifconfig {} mtu 9216".format(r0_r1_intf))
    rtr1.run("ifconfig {} mtu 9216".format(r1_r0_intf))

    clear_ospf(tgen, "r0", ospf="ospf6")
    clear_ospf(tgen, "r1", ospf="ospf6")

    step("Verify that OSPF neighborship between R0 and R1 becomes full.")
    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that jumbo MTU is updated in the show ip ospf interface.")
    dut = "r0"
    input_dict = {"r0": {"links": {"r1": {"ospf6": {"interfaceMtu": 9216}}}}}
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospfv3_show_p1(request):
    """Verify ospf show commands with json output."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    input_dict = {"r2": {"debug": {"log_file": "debug.log", "enable": ["ospf6"]}}}

    result = create_debug_log_config(tgen, input_dict)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    step(" Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    dut = "r1"
    input_dict = {
        "r1": {
            "links": {
                "r0": {
                    "ospf6": {
                        "status": "up",
                        "type": "BROADCAST",
                        "attachedToArea": True,
                        "instanceId": 0,
                        "interfaceMtu": 1500,
                        "autoDetect": 1500,
                        "mtuMismatchDetection": "enabled",
                        "areaId": "0.0.0.0",
                        "cost": 10,
                        "transmitDelaySec": 1,
                        "priority": 1,
                        "timerIntervalsConfigHello": 1,
                        "timerIntervalsConfigDead": 4,
                        "timerIntervalsConfigRetransmit": 5,
                        "dr": "0.0.0.0",
                        "bdr": "0.0.0.0",
                        "numberOfInterfaceScopedLsa": 2,
                        "pendingLsaLsUpdateCount": 0,
                        "lsUpdateSendThread": "off",
                        "pendingLsaLsAckCount": 0,
                        "lsAckSendThread": "off",
                    }
                }
            }
        }
    }
    result = verify_ospf6_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ip = topo["routers"]["r0"]["links"]["r3"]["ipv6"]
    ip_net = str(ipaddress.ip_interface("{}".format(ip)).network)
    nh = topo["routers"]["r0"]["links"]["r1"]["ipv6"].split("/")[0]
    input_dict = {
        "r1": {
            "static_routes": [
                {"network": ip_net, "no_of_ip": 1, "routeType": "Network"}
            ]
        }
    }

    dut = "r1"
    result = verify_ospf6_rib(tgen, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def ospfv3_router_id_tc14_p2(request):
    """OSPF Router ID - Verify OSPF router id changes."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step(" Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure system router id as 1.1.1.1 on R1 , clear ospf router")
    ospf_rid = {"r0": {"ospf6": {"router_id": "1.1.1.1"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("configure ospf router id as 1.1.1.2 on R1, clear ospf router")
    ospf_rid = {"r1": {"ospf6": {"router_id": "1.1.1.2"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    topo1 = deepcopy(topo)
    step("Verify that OSPF takes system router ID as ospf router id.")

    topo1["routers"]["r0"]["ospf6"]["router_id"] = "1.1.1.1"
    topo1["routers"]["r1"]["ospf6"]["router_id"] = "1.1.1.2"

    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    ospf_covergence = verify_ospf6_neighbor(tgen, topo1)
    assert ospf_covergence is True, "OSPF NBRs not up.Failed \n Error:  {}".format(
        ospf_covergence
    )

    step(" delete ospf router id and clear ospf process.")
    ospf_rid = {"r0": {"ospf6": {"del_router_id": "1.1.1.1"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_rid = {"r1": {"ospf6": {"del_router_id": "1.1.1.2"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    reset_config_on_routers(tgen)

    step(" Configure R0 R1 R2 with same router ids")
    ospf_rid = {"r0": {"ospf6": {"router_id": "1.1.1.1"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("configure ospf router id as 1.1.1.2 on R1, reboot router")
    ospf_rid = {"r1": {"ospf6": {"router_id": "1.1.1.1"}}}
    result = create_router_ospf(tgen, topo, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, expected=False)
    assert ospf_covergence is not True, "OSPF NBRs are up.Failed \n Error:  {}".format(
        ospf_covergence
    )
    topo1 = {}
    topo1 = deepcopy(topo)

    for rtr in ["r1", "r2", "r3", "r0"]:
        topo1["routers"][rtr]["ospf6"].pop("router_id")

    build_config_from_json(tgen, topo1, save_bkup=False)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is not True, (
        "Testcase {} :Failed \n Neighborship "
        "should not up as no router id is configured. Error: {}".format(tc_name, result)
    )

    step("Clear ospf process and check nbrs should not be up.")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is not True, (
        "Testcase {} :Failed \n Neighborship "
        "should not up as no router id is configured. Error: {}".format(tc_name, result)
    )

    topo1 = deepcopy(topo)

    step("Configure system router id on routers , clear ospf router")
    ospf_rid = {
        "r0": {"ospf6": {"router_id": "1.1.1.1"}},
        "r1": {"ospf6": {"router_id": "1.1.1.2"}},
        "r2": {"ospf6": {"router_id": "1.1.1.3"}},
        "r3": {"ospf6": {"router_id": "1.1.1.4"}},
    }
    result = create_router_ospf(tgen, topo1, ospf_rid)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    topo1["routers"]["r0"]["ospf6"]["router_id"] = "1.1.1.1"
    topo1["routers"]["r1"]["ospf6"]["router_id"] = "1.1.1.2"
    topo1["routers"]["r2"]["ospf6"]["router_id"] = "1.1.1.3"
    topo1["routers"]["r3"]["ospf6"]["router_id"] = "1.1.1.4"

    ospf_covergence = verify_ospf6_neighbor(tgen, topo1)
    assert ospf_covergence is True, "OSPF NBRs not up.Failed \n Error:  {}".format(
        ospf_covergence
    )

    step(" Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo)
    assert ospf_covergence is True, "OSPF NBRs not up.Failed \n Error:  {}".format(
        ospf_covergence
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
