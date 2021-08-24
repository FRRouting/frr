#!/usr/bin/python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
import json
from time import sleep
from copy import deepcopy
import ipaddress

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
from lib.topogen import Topogen, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    step,
    create_route_maps,
    shutdown_bringup_interface,
    create_interfaces_cfg,
    topo_daemons,
    scapy_send_raw_packet,
)

from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

from lib.ospf import (
    verify_ospf6_neighbor,
    clear_ospf,
    verify_ospf6_gr_helper,
    create_router_ospf,
    verify_ospf6_interface,
    verify_ospf6_database,
)

# Global variables
topo = None
Iters = 5
sw_name = None
intf = None
intf1 = None
pkt = None

# Reading the data from JSON File for topology creation
jsonFile = "{}/ospfv3_gr_helper.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

"""
Topology:

      Please view in a fixed-width font such as Courier.
      Topo : Broadcast Networks
      DUT - HR      RR
        +---+       +---+          +---+           +---+
        |R0 +       +R1 +          +R2 +           +R3 |
        +-+-+       +-+-+          +-+-+           +-+-+
          |           |              |               |
          |           |              |               |
        --+-----------+--------------+---------------+-----
                         Ethernet Segment

"""


class CreateTopo(Topo):
    """
    Test topology builder.

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function."""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, intf, intf1, sw_name, pkt
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(CreateTopo, mod.__name__)
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

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert ospf_covergence is True, "setup_module :Failed \n Error:" " {}".format(
        ospf_covergence
    )

    sw_name = topo["switches"].keys()[0]
    intf = topo["routers"]["r0"]["links"][sw_name]["interface"]
    intf1 = topo["routers"]["r1"]["links"][sw_name]["interface"]
    pkt = topo["routers"]["r1"]["opq_lsa_hex"]

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    try:
        # Stop toplogy and Remove tmp files
        tgen.stop_topology

    except OSError:
        # OSError exception is raised when mininet tries to stop switch
        # though switch is stopped once but mininet tries to stop same
        # switch again, where it ended up with exception
        pass


def delete_ospf():
    """delete ospf process after each test"""
    tgen = get_topogen()
    step("Delete ospf process")
    for rtr in topo["routers"]:
        ospf_del = {rtr: {"ospf6": {"delete": True}}}
        result = create_router_ospf(tgen, topo, ospf_del)
        assert result is True, "Testcase Cleaup Failed \n Error: {}".format(result)


# ##################################
# Test cases start here.
# ##################################


def test_ospfv3_gr_helper_tc1_p0(request):
    """Verify by default helper support is disabled for FRR ospf"""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)

    step("Verify that GR helper route is disabled by default to the in" "the DUT.")
    input_dict = {
        "helperSupport": "Disabled",
        "strictLsaCheck": "Enabled",
        "restartSupoort": "Planned and Unplanned Restarts",
        "supportedGracePeriod": 1800,
    }
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT does not enter helper mode upon receiving the " "grace lsa.")

    # send grace lsa
    scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)

    input_dict = {"activeRestarterCnt": 1}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed. DUT entered helper role " " \n Error: {}".format(
        tc_name, result
    )

    step("Configure graceful restart in the DUT")
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that GR helper route is enabled in the DUT.")
    input_dict = {
        "helperSupport": "Enabled",
        "strictLsaCheck": "Enabled",
        "restartSupoort": "Planned and Unplanned Restarts",
        "supportedGracePeriod": 1800,
    }
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR in RR.")
    step("Verify that DUT does enter helper mode upon receiving" " the grace lsa.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Unconfigure the GR helper command.")
    ospf_gr_r0 = {
        "r0": {"ospf6": {"graceful-restart": {"helper-only": [], "delete": True}}}
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"helperSupport": "Disabled"}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure gr helper using the router id")
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": ["1.1.1.1"],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that GR helper router is enabled in the DUT for " "router id x.x.x.x")

    input_dict = {
        "helperSupport": "Disabled",
        "enabledRouterIds": [{"routerId": "1.1.1.1"}],
    }
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT does enter helper mode upon receiving" " the grace lsa.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Un Configure gr helper using the router id")
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {"graceful-restart": {"helper-only": ["1.1.1.1"], "delete": True}}
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that GR helper router is disabled in the DUT for" " router id x.x.x.x")
    input_dict = {"enabledRouterIds": [{"routerId": "1.1.1.1"}]}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed, Helper role enabled for RR\n Error: {}".format(
        tc_name, result
    )
    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc2_p0(request):
    """
    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
    sends grace lsa, helps RR to restart gracefully (RR = DR)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc3_p1(request):
    """
    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
    sends grace lsa, helps RR to restart gracefully (RR = BDR)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    step(
        "Configure DR pririty 100 on R0 and clear ospf neighbors " "on all the routers."
    )

    input_dict = {
        "r0": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r0"]["links"][sw_name]["interface"],
                    "ospf6": {"priority": 100},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    step("Verify that DR election is triggered and R0 is elected as DR")
    input_dict = {
        "r0": {
            "ospf6": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "Backup"},
                    "r2": {"state": "Full", "role": "DROther"},
                    "r3": {"state": "Full", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc4_p1(request):
    """
    OSPF GR on Broadcast : Verify DUT enters Helper mode when neighbor
    sends grace lsa, helps RR to restart gracefully (RR = DRother)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    step(
        "Configure DR pririty 100 on R0 and clear ospf neighbors " "on all the routers."
    )

    input_dict = {
        "r0": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r0"]["links"][sw_name]["interface"],
                    "ospf6": {"priority": 0},
                }
            }
        }
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    step("Verify that DR election is triggered and R0 is elected as 2-Way")
    input_dict = {
        "r0": {
            "ospf6": {
                "neighbors": {
                    "r1": {"state": "Full", "role": "DR"},
                    "r2": {"state": "2-Way", "role": "DROther"},
                    "r3": {"state": "2-Way", "role": "DROther"},
                }
            }
        }
    }
    dut = "r0"
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc5_p0(request):
    """
    OSPF GR on P2P : Verify DUT enters Helper mode when neighbor sends
    grace lsa, helps RR to restart gracefully.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step("Configure DR priority as 0 on R1 & R2 and network p2p between r0 r1")

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    input_dict = {
        "r0": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r0"]["links"][sw_name]["interface"],
                    "ospf6": {"network": "point-to-point"},
                }
            }
        },
        "r1": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r1"]["links"][sw_name]["interface"],
                    "ospf6": {"network": "point-to-point"},
                }
            }
        },
        "r2": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r2"]["links"][sw_name]["interface"],
                    "ospf6": {
                        "area": "0",
                    },
                    "delete": True,
                }
            }
        },
        "r3": {
            "links": {
                sw_name: {
                    "interface": topo["routers"]["r3"]["links"][sw_name]["interface"],
                    "ospf6": {"area": "0"},
                    "delete": True,
                }
            }
        },
    }

    result = create_interfaces_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Clear ospf neighbours in all routers")
    for rtr in topo["routers"]:
        clear_ospf(tgen, rtr, ospf="ospf6")

    step("Verify that DR election is triggered and R0 is elected as DRother")
    input_dict = {
        "r0": {"ospf6": {"neighbors": {"r1": {"state": "Full", "role": "-"}}}}
    }
    dut = "r0"
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc24_p2(request):
    """
    Test ospf gr helper
    CLI Test- Multiple times add/delete operations with using
    "show memory".
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc23_p2(request):
    """
    Test ospf gr helper
    Verify all the show commands newly introducted as part of ospf
    helper support - Json Key verification wrt to show commands.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Perform GR and Verify that RR restarts and sends Grace LSA to DUT.")
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("show ip ospf neighbor")
    input_dict = {
        "r0": {
            "ospf6": {"neighbors": {"r1": {"state": "Full", "grHelperStatus": "Yes"}}}
        }
    }
    dut = "r0"
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict, lan=True)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc19_p1(request):
    """
    Test ospf gr helper
    Verify helper when grace lsa is received with different configured
    value in process level (higher, lower, grace lsa timer above 1800)
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step(
        "Configure DR priority as 99 in RR , DUT dr priority = 98 "
        "& reset ospf process in all the routers"
    )
    step(
        "Enable GR on RR and DUT with grace period on RR = 333"
        "and grace period on DUT = 300"
    )

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"supportedGracePeriod": 1800}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure grace period = 1801 on RR and restart ospf .")
    grace_period_1801 = "01005e00000570708bd051ef080045c0005cbeb10000015907d111010101e00000050204004801010101000000009714000000000000000000000000000100010209030000000101010180000001c8e9002c000100040000016800020001010000000003000411010101"
    gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, grace_period_1801)

    step("Verify R0 does not enter helper mode.")
    input_dict = {"activeRestarterCnt": 1}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed. DUT entered helper role " " \n Error: {}".format(
        tc_name, result
    )

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc7_p1(request):
    """
    Test ospf gr helper

    Verify helper functionality when dut is helping RR and new grace lsa
    is received from RR.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step("Enable GR")

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"supportedGracePeriod": 1800}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Send the Grace LSA again to DUT when RR is in GR.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that new Grace LSA is received and GR timer is updated with "
        "new time ( current running time + new grace time received )"
    )
    input_dict = {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {"lsaId": "3.0.0.0", "advertisedRouter": "1.1.1.1"}
                ]
            }
        }
    }
    result = verify_ospf6_database(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc11_p1(request):
    """
    Test ospf gr helper

    verify helper functionality when topo change is detected
    (topo change events - new lsa added/ lsa is deleted).
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step("Enable GR")

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"supportedGracePeriod": 1800}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    network = {
        "ipv4": [
            "11.0.20.1/32",
            "11.0.20.2/32",
            "11.0.20.3/32",
            "11.0.20.4/32",
            "11.0.20.5/32",
        ],
        "ipv6": [
            "11:0:20::1/128",
            "11:0:20::2/128",
            "11:0:20::3/128",
            "11:0:20::4/128",
            "11:0:20::5/128",
        ],
    }
    input_dict = {
        "r2": {
            "static_routes": [
                {
                    "network": network["ipv6"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_red = {
        "r2": {
            "ospf6": {
                "redistribute": [
                    {
                        "redist_type": "static",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("When RR is in GR, undo import static routes with cost in R2.")
    ospf_red = {
        "r2": {"ospf6": {"redistribute": [{"redist_type": "static", "delete": True}]}}
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    input_dict = {"LastExitReason": "Topology Change"}
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that no DUT is not helping RR.")
    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is not True, "Testcase {} : Failed \n Error: {}".format(
        tc_name, result
    )

    step(
        "Verify that DUT detects the topo change."
        "Verify that DUT exits the GR with topo change event."
        "Verify that GR status exit reason is updated to - Failed : Topo change."
    )

    ospf_red = {
        "r2": {
            "ospf6": {
                "redistribute": [
                    {
                        "redist_type": "static",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    input_dict = {"LastExitReason": "Topology Change"}
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc12_p1(request):
    """
    Test ospf gr helper
    verify helper functionality when topo change is detected
    (topo change events - neighbor deleted)
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step("Enable GR")

    reset_config_on_routers(tgen)

    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"supportedGracePeriod": 1800}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Delete ospf process on HR2.")
    ospf_r2 = {"r2": {"ospf6": {"delete": True}}}
    result = create_router_ospf(tgen, topo, ospf_r2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that DUT detects the topo change."
        "Verify that DUT exits the GR with topo change event."
        "Verify that GR status exit reason is updated to - "
        "Failed : Topo change."
    )

    input_dict = {"LastExitReason": "Topology Change"}
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


def test_ospfv3_gr_helper_tc14_p0(request):
    """
    Test ospf gr helper

    Verify topo change is not detected for LSA changes when strict LSA
    check is disabled.
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo, intf, intf1, pkt

    step("Bring up the base config as per the topology")
    step("Enable GR")
    reset_config_on_routers(tgen)
    ospf_covergence = verify_ospf6_neighbor(tgen, topo, lan=True)
    assert (
        ospf_covergence is True
    ), "OSPF is not after reset config \n Error:" " {}".format(ospf_covergence)
    ospf_gr_r0 = {
        "r0": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                    "helper": ["lsa-check-disable"],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r0)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                    "helper": ["lsa-check-disable"],
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {"supportedGracePeriod": 1800}
    dut = "r0"
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    network = {
        "ipv4": [
            "11.0.20.1/32",
            "11.0.20.2/32",
            "11.0.20.3/32",
            "11.0.20.4/32",
            "11.0.20.5/32",
        ],
        "ipv6": [
            "11:0:20::1/128",
            "11:0:20::2/128",
            "11:0:20::3/128",
            "11:0:20::4/128",
            "11:0:20::5/128",
        ],
    }
    input_dict = {
        "r2": {
            "static_routes": [
                {
                    "network": network["ipv6"][0],
                    "no_of_ip": 5,
                    "next_hop": "Null0",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    ospf_red = {
        "r2": {
            "ospf6": {
                "redistribute": [
                    {
                        "redist_type": "static",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    step("Verify that DUT enters into helper mode.")

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("When RR is in GR, undo import static routes with cost in R2.")
    ospf_red = {
        "r2": {"ospf6": {"redistribute": [{"redist_type": "static", "delete": True}]}}
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    input_dict = {"LastExitReason": "Topology Change"}
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert (
        result is not True
    ), "Testcase {} : Failed. GR Failed. " "\n Error: {}".format(tc_name, result)

    input_dict = {"activeRestarterCnt": 1}
    gracelsa_sent = False
    repeat = 0
    dut = "r0"
    while not gracelsa_sent and repeat < Iters:
        gracelsa_sent = scapy_send_raw_packet(tgen, topo, "r1", intf1, pkt)
        result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
        if isinstance(result, str):
            repeat += 1
            gracelsa_sent = False

    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that DUT detects the topo change."
        "Verify that DUT exits the GR with topo change event."
        "Verify that GR status exit reason is updated to - Failed : Topo change."
    )

    ospf_red = {
        "r2": {
            "ospf6": {
                "redistribute": [
                    {
                        "redist_type": "static",
                    }
                ]
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)

    input_dict = {"LastExitReason": "Topology Change"}
    result = verify_ospf6_gr_helper(tgen, topo, dut, input_dict)
    assert result is not True, "Testcase {} : GR Failed. Failed \n Error: {}".format(
        tc_name, result
    )

    step("delete lsa-check-disable cmd")

    ospf_gr_r1 = {
        "r1": {
            "ospf6": {
                "graceful-restart": {
                    "helper-only": [],
                    "helper": ["lsa-check-disable"],
                    "delete": True,
                }
            }
        }
    }
    result = create_router_ospf(tgen, topo, ospf_gr_r1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    delete_ospf()

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
