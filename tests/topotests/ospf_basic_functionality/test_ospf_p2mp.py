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
import os
import sys
import time
import pytest
from copy import deepcopy
from ipaddress import IPv4Address

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
    topo_daemons,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.topotest import frr_unicode

from lib.ospf import (
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
1. OSPF P2MP -Verify state change events on p2mp network.
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
    json_file = "{}/ospf_p2mp.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
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


def test_ospf_p2mp_tc1_p0(request):
    """OSPF IFSM -Verify state change events on p2mp network."""
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

    step("Verify if interface is enabled with network type P2MP")
    input_dict = {
        "r0": {
            "links": {
                "r3": {
                    "interface": topo["routers"]["r0"]["links"]["r3"]["interface"],
                    "ospf": {"area": "0.0.0.0", "networkType": "POINTOMULTIPOINT"},
                }
            }
        }
    }
    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
