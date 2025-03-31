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
    retry,
    run_frr_cmd,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.topotest import frr_unicode, json_cmp

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

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

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


def test_ospf_p2mp_tc_delay_reflood(request):
    """OSPF IFSM -Verify "delay-reflood" parameter in p2mp network."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    r0 = tgen.gears["r0"]

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo

    step("Verify for interface with network type P2MP that delay-reflood is configured")
    r0.vtysh_multicmd(
        "conf t\ninterface r0-r1-eth0\nip ospf network point-to-multipoint delay-reflood"
    )

    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": True,
                    }
                },
                "r2": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
                "r3": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    delay_reflood_cfg = (
        tgen.net["r0"]
        .cmd(
            'vtysh -c "show running" | grep "^ ip ospf network point-to-multipoint delay-reflood"'
        )
        .rstrip()
    )

    assertmsg = "delay-reflood' configuration applied, but not present in configuration"
    assert (
        delay_reflood_cfg == " ip ospf network point-to-multipoint delay-reflood"
    ), assertmsg

    step("Verify for interface with network type P2MP that delay-reflood is removed")
    r0.vtysh_multicmd(
        "conf t\ninterface r0-r1-eth0\nip ospf network point-to-multipoint"
    )

    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
                "r2": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
                "r3": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delay_reflood_cfg = (
        tgen.net["r0"]
        .cmd(
            'vtysh -c "show running" | grep "^ ip ospf network point-to-multipoint delay-reflood"'
        )
        .rstrip()
    )
    assertmsg = (
        "delay-reflood' configuration removed, but still present in configuration"
    )
    assert (
        delay_reflood_cfg != " ip ospf network point-to-multipoint delay-reflood"
    ), assertmsg

    step(
        "Verify for interface with network type P2MP that delay-reflood is removed with removal of network type"
    )
    r0.vtysh_multicmd(
        "conf t\ninterface r0-r1-eth0\nip ospf network point-to-multipoint delay-reflood"
    )
    r0.vtysh_multicmd(
        "conf t\ninterface r0-r1-eth0\nno ip ospf network point-to-multipoint"
    )
    r0.vtysh_multicmd(
        "conf t\ninterface r0-r1-eth0\nip ospf network point-to-multipoint"
    )

    input_dict = {
        "r0": {
            "links": {
                "r1": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
                "r2": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
                "r3": {
                    "ospf": {
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                        "networkType": "POINTOMULTIPOINT",
                        "p2mpDelayReflood": False,
                    }
                },
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delay_reflood_cfg = (
        tgen.net["r0"]
        .cmd(
            'vtysh -c "show running" | grep "^ ip ospf network point-to-multipoint delay-reflood"'
        )
        .rstrip()
    )
    assertmsg = (
        "delay-reflood' configuration removed, but still present in configuration"
    )
    assert (
        delay_reflood_cfg != " ip ospf network point-to-multipoint delay-reflood"
    ), assertmsg

    write_test_footer(tc_name)


@retry(retry_timeout=30)
def verify_ospf_json(tgen, dut, input_dict, cmd="show ip ospf database json"):
    del tgen
    show_ospf_json = run_frr_cmd(dut, cmd, isjson=True)
    if not bool(show_ospf_json):
        return "ospf is not running"
    result = json_cmp(show_ospf_json, input_dict)
    return str(result) if result else None


@pytest.mark.parametrize("tgen", [2], indirect=True)
def test_ospf_nbrs(tgen):
    db_full = {
        "areas": {
            "0.0.0.0": {
                "routerLinkStates": [
                    {
                        "lsId": "100.1.1.0",
                        "advertisedRouter": "100.1.1.0",
                        "numOfRouterLinks": 6,
                    },
                    {
                        "lsId": "100.1.1.1",
                        "advertisedRouter": "100.1.1.1",
                        "numOfRouterLinks": 6,
                    },
                    {
                        "lsId": "100.1.1.2",
                        "advertisedRouter": "100.1.1.2",
                        "numOfRouterLinks": 6,
                    },
                    {
                        "lsId": "100.1.1.3",
                        "advertisedRouter": "100.1.1.3",
                        "numOfRouterLinks": 7,
                    },
                ]
            }
        }
    }
    input = [
        [
            "r0",
            "show ip ospf n json",
            {
                "neighbors": {
                    "100.1.1.1": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.2": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.3": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                }
            },
        ],
        [
            "r1",
            "show ip ospf n json",
            {
                "neighbors": {
                    "100.1.1.0": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.2": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.3": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                }
            },
        ],
        [
            "r2",
            "show ip ospf n json",
            {
                "neighbors": {
                    "100.1.1.0": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.1": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.3": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                }
            },
        ],
        [
            "r3",
            "show ip ospf n json",
            {
                "neighbors": {
                    "100.1.1.0": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.1": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                    "100.1.1.2": [
                        {
                            "nbrState": "Full/DROther",
                        }
                    ],
                }
            },
        ],
        ["r0", "show ip ospf database json", db_full],
        ["r1", "show ip ospf database json", db_full],
        ["r2", "show ip ospf database json", db_full],
        ["r3", "show ip ospf database json", db_full],
        ["r0", "show ip ospf database json", db_full],
        ["r0", "show ip ospf database router json", {}],
        ["r0", "show ip ospf interface traffic json", {}],
        ["r1", "show ip ospf interface traffic json", {}],
        ["r2", "show ip ospf interface traffic json", {}],
        ["r3", "show ip ospf interface traffic json", {}],
    ]
    for cmd_set in input:
        step("test_ospf: %s - %s" % (cmd_set[0], cmd_set[1]))
        assert (
            verify_ospf_json(tgen, tgen.gears[cmd_set[0]], cmd_set[2], cmd_set[1])
            is None
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
