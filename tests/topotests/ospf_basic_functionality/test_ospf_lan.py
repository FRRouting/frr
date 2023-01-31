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
    create_interfaces_cfg,
    write_test_footer,
    reset_config_on_routers,
    step,
    shutdown_bringup_interface,
    stop_router,
    start_router,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import (
    verify_ospf_neighbor,
    clear_ospf,
    create_router_ospf,
    verify_ospf_interface,
)
from ipaddress import IPv4Address

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
    ]
}

"""
Topology:

      Please view in a fixed-width font such as Courier.
      Topo : Broadcast Networks
        +---+       +---+          +---+           +---+
        |R0 +       +R1 +          +R2 +           +R3 |
        +-+-+       +-+-+          +-+-+           +-+-+
          |           |              |               |
          |           |              |               |
        --+-----------+--------------+---------------+-----
                         Ethernet Segment

Testcases:
1.     OSPF Hello protocol - Verify DR BDR Elections
2.     OSPF IFSM -Verify state change events on DR / BDR / DR Other

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
    json_file = "{}/ospf_lan.json".format(CWD)
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
    ospf_covergence = verify_ospf_neighbor(tgen, topo, lan=True)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    try:
        # Stop toplogy and Remove tmp files
        tgen.stop_topology()

    except OSError:
        # OSError exception is raised when mininet tries to stop switch
        # though switch is stopped once but mininet tries to stop same
        # switch again, where it ended up with exception
        pass


# ##################################
# Test cases start here.
# ##################################


def test_ospf_lan_tc1_p0(request):
    """
    OSPF Hello protocol - Verify DR BDR Elections

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
    step("Verify that DR BDR DRother are elected in the LAN.")
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "DR"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that all the routers are in FULL state with DR and BDR "
        "in the topology"
    )

    input_dict = {
        "r1": {
            "ospf": {
                "neighbors": {
                    "r0": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r1"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure DR pririty 100 on R0 and clear ospf neighbors " "on all the routers."
    )

    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"priority": 100},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in ["r0", "r1", "r2", "r3"]:
        clear_ospf(tgen, rtr)

    step("Verify that DR election is triggered and R0 is elected as DR")
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure DR pririty 150 on R0 and clear ospf neighbors " "on all the routers."
    )

    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"priority": 150},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in ["r0", "r1"]:
        clear_ospf(tgen, rtr)

    step("Verify that DR election is triggered and R0 is elected as DR")
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure DR priority 0 on R0 & Clear ospf nbrs on all the routers")

    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"priority": 0},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in ["r1"]:
        clear_ospf(tgen, rtr)

    step("Verify that DR election is triggered and R0 is elected as DRother")
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "DR"},
                    "r2": {"state": "2-Way", "role": "DROther"},
                    "r3": {"state": "2-Way", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure DR priority to default on R0 and Clear ospf neighbors"
        " on all the routers"
    )

    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"priority": 100},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in ["r0", "r1"]:
        clear_ospf(tgen, rtr)

    step("Verify that DR election is triggered and R0 is elected as DR")
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["s1"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    result = verify_ospf_neighbor(tgen, topo, dut, lan=True, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "r0: OSPF neighbors-hip is up \n Error: {}".format(
        tc_name, result
    )

    step("No Shut interface on R0")
    dut = "r0"
    intf = topo["routers"]["r0"]["links"]["s1"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, True)

    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "DR"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    step("Verify that after no shut ospf neighbours are full on R0.")
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf on DR router in the topology.")
    clear_ospf(tgen, "r0")

    step("Verify that BDR is getting promoted to DR after clear.")
    step("Verify that all the nbrs are in FULL state with the elected DR.")
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ip on LAN intf on R0 to other ip from the same subnet.")
    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"]
    topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 4
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)

    clear_ospf(tgen, "r0")
    step(
        "Verify that OSPF is in FULL state with other routers with "
        "newly configured IP."
    )
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ospf router id on the R0 and clear ip ospf interface.")
    change_rid = {"r0": {"ospf": {"router_id": "100.1.1.100"}}}

    result = create_router_ospf(tgen, topo, change_rid)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    topo["routers"]["r0"]["ospf"]["router_id"] = "100.1.1.100"
    step("Reload the FRR router")

    stop_router(tgen, "r0")
    start_router(tgen, "r0")

    step(
        "Verify that OSPF is in FULL state with other routers with"
        " newly configured router id."
    )
    input_dict = {
        "r1": {
            "ospf": {
                "neighbors": {
                    "r0": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r1"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Reconfigure the original router id and clear ip ospf interface.")
    change_rid = {"r0": {"ospf": {"router_id": "100.1.1.0"}}}
    result = create_router_ospf(tgen, topo, change_rid)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    topo["routers"]["r0"]["ospf"]["router_id"] = "100.1.1.0"
    step("Reload the FRR router")
    # stop/start -> restart FRR router and verify
    stop_router(tgen, "r0")
    start_router(tgen, "r0")

    step("Verify that OSPF is enabled with router id previously configured.")
    input_dict = {
        "r1": {
            "ospf": {
                "neighbors": {
                    "r0": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r1"
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ospf_lan_tc2_p0(request):
    """
    OSPF IFSM -Verify state change events on DR / BDR / DR Other

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
    step(
        "Verify that OSPF is subscribed to multi cast services "
        "(All SPF, all DR Routers)."
    )
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "ospf": {
                        "priority": 98,
                        "timerDeadSecs": 4,
                        "area": "0.0.0.3",
                        "mcastMemberOspfDesignatedRouters": True,
                        "mcastMemberOspfAllRouters": True,
                        "ospfEnabled": True,
                    }
                }
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
                    "ipv4": topo["routers"]["r0"]["links"]["s1"]["ipv4"],
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ip on the R0 interface")

    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"]
    topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(intf_ip.split("/")[1])

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "ospf": {
                        "ipAddress": topo_modify_change_ip["routers"]["r0"]["links"][
                            "s1"
                        ]["ipv4"].split("/")[0],
                        "ipAddressPrefixlen": int(
                            topo_modify_change_ip["routers"]["r0"]["links"]["s1"][
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
    ip_addr = topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"]
    mask = topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"]
    step("Delete the ip address")
    topo1 = {
        "r0": {
            "links": {
                "r3": {
                    "ipv4": ip_addr,
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "delete": True,
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, topo1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Change the ip on the R0 interface")

    topo_modify_change_ip = deepcopy(topo)
    intf_ip = topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"]
    topo_modify_change_ip["routers"]["r0"]["links"]["s1"]["ipv4"] = str(
        IPv4Address(frr_unicode(intf_ip.split("/")[0])) + 3
    ) + "/{}".format(int(intf_ip.split("/")[1]) + 1)

    build_config_from_json(tgen, topo_modify_change_ip, save_bkup=False)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "ospf": {
                        "ipAddress": topo_modify_change_ip["routers"]["r0"]["links"][
                            "s1"
                        ]["ipv4"].split("/")[0],
                        "ipAddressPrefixlen": int(
                            topo_modify_change_ip["routers"]["r0"]["links"]["s1"][
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

    step("Change the area id on the interface")
    input_dict = {
        "r0": {
            "links": {
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"area": "0.0.0.3"},
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
                "s1": {
                    "interface": topo["routers"]["r0"]["links"]["s1"]["interface"],
                    "ospf": {"area": "0.0.0.2"},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)
    step("Verify that interface is enabled in ospf.")
    dut = "r0"
    input_dict = {
        "r0": {"links": {"s1": {"ospf": {"area": "0.0.0.2", "ospfEnabled": True}}}}
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
