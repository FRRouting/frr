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

"""
Following tests are covered to test Multicast basic functionality:

Topology:

                 _______r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4

Test steps
- Create topology (setup module)
- Bring up topology

TC_1 : Verify upstream interfaces(IIF) and join state are updated properly
       after adding and deleting the static RP
TC_2 : Verify IIF and OIL in "show ip pim state" updated properly after
       adding and deleting the static RP
TC_3: (*, G) Mroute entry are cleared when static RP gets deleted
TC_4: Verify (*,G) prune is send towards the RP after deleting the static RP
TC_24 : Verify (*,G) and (S,G) populated correctly when SPT and RPT share the
        same path
"""

import os
import sys
import json
import time
import pytest
from time import sleep
import datetime

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
    shutdown_bringup_interface,
    kill_router_daemons,
    start_router_daemons,
    create_static_routes,
    check_router_status,
    socat_send_igmp_join_traffic,
    topo_daemons
)
from lib.pim import (
    create_pim_config,
    verify_igmp_groups,
    verify_upstream_iif,
    verify_join_state_and_timer,
    verify_mroutes,
    verify_pim_neighbors,
    verify_pim_interface_traffic,
    verify_pim_rp_info,
    verify_pim_state,
    clear_pim_interface_traffic,
    clear_igmp_interfaces,
    clear_pim_interfaces,
    clear_mroute,
    clear_mroute_verify,
)
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json

# Global variables
GROUP_RANGE_V6 = "ff08::/64"
IGMP_JOIN_V6 = "ff08::1"
STAR = "*"
SOURCE = "Static"

pytestmark = [pytest.mark.pimd]


def build_topo(tgen):
    """Build function"""

    # Building topology from json file
    build_topo_from_json(tgen, TOPO)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: %s", testsuite_run_time)
    logger.info("=" * 40)

    topology = """

                 _______r2_____
                |             |
      iperf     |             |     iperf
        r0-----r1-------------r3-----r5
                |             |
                |_____________|
                        r4

    """
    logger.info("Master Topology: \n %s", topology)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/multicast_pimv6_static_rp.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global TOPO
    TOPO = tgen.json_topo

    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, TOPO)

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen, daemons)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, TOPO)

    # Verify PIM neighbors
    result = verify_pim_neighbors(tgen, TOPO)
    assert result is True, "setup_module :Failed \n Error:" " {}".format(result)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")
    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: %s", time.asctime(time.localtime(time.time())))
    logger.info("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for router, state_data in state_before.items():
        for state, value in state_data.items():
            if state_before[router][state] >= state_after[router][state]:
                errormsg = (
                    "[DUT: %s]: state %s value has not"
                    " incremented, Initial value: %s, "
                    "Current value: %s [FAILED!!]"
                    % (
                        router,
                        state,
                        state_before[router][state],
                        state_after[router][state],
                    )
                )
                return errormsg

            logger.info(
                "[DUT: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]",
                router,
                state,
                state_before[router][state],
                state_after[router][state],
            )

    return True


#####################################################

def test_pimv6_add_delete_static_RP_p0(request):
    """
    TC_1: Verify upstream interfaces(IIF) and join state are updated
        properly after adding and deleting the static RP
    TC_2: Verify IIF and OIL in "show ip pim state" updated properly
        after adding and deleting the static RP
    TC_3: (*, G) Mroute entry are cleared when static RP gets deleted
    TC_4: Verify (*,G) prune is send towards the RP after deleting the
        static RP

    TOPOlogy used:
         r0------r1-----r2
       iperf    DUT     RP
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Shut link b/w R1 and R3 and R1 and R4 as per tescase topology")
    intf_r1_r3 = TOPO["routers"]["r1"]["links"]["r3"]["interface"]
    intf_r1_r4 = TOPO["routers"]["r1"]["links"]["r4"]["interface"]
    for intf in [intf_r1_r3, intf_r1_r4]:
        shutdown_bringup_interface(tgen, "r1", intf, ifaceaction=False)

    step("Enable PIM between r1 and r2")
    step("Enable MLD on r1 interface and send IGMP " "join (FF08::1) to r1")
    step("Configure r2 loopback interface as RP")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_V6,
                    }
                ]
            }
        }
    }

    assert True
    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify show ip pim interface traffic without any mld join")
    state_dict = {
        "r1": {TOPO["routers"]["r1"]["links"]["r2"]["interface"]: ["pruneTx"]}
    }

    state_before = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("send mld join (FF08::1) to R1")
    intf = TOPO["routers"]["r0"]["links"]["r1"]["interface"]
    intf_ip = TOPO["routers"]["r0"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_igmp_join_traffic(
        tgen, "r0", "UDP6-RECV", IGMP_JOIN_V6, intf, intf_ip, join=True
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    dut = "r1"
    oif = TOPO["routers"]["r1"]["links"]["r2"]["interface"]
    iif = TOPO["routers"]["r1"]["links"]["r0"]["interface"]
    rp_address = TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_V6, oif, rp_address, SOURCE
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, oif, STAR, IGMP_JOIN_V6)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(tgen, dut, oif, STAR, IGMP_JOIN_V6)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, oif, iif, IGMP_JOIN_V6)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, IGMP_JOIN_V6, oif, iif)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("r1: Delete RP configuration")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": TOPO["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_V6,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, TOPO, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1: Verify RP info")
    result = verify_pim_rp_info(
        tgen, TOPO, dut, GROUP_RANGE_V6, oif, rp_address, SOURCE, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} :Failed \n " "RP: {} info is still present \n Error: {}".format(
        tc_name, rp_address, result
    )

    step("r1: Verify upstream IIF interface")
    result = verify_upstream_iif(tgen, dut, oif, STAR, IGMP_JOIN_V6, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "Upstream ({}, {}) is still in join state \n Error: {}".format(
            tc_name, STAR, IGMP_JOIN_V6, result
        )
    )

    step("r1: Verify upstream join state and join timer")
    result = verify_join_state_and_timer(
        tgen, dut, oif, STAR, IGMP_JOIN_V6, expected=False
    )
    assert result is not True, (
        "Testcase {} :Failed \n "
        "Upstream ({}, {}) timer is still running \n Error: {}".format(
            tc_name, STAR, IGMP_JOIN_V6, result
        )
    )

    step("r1: Verify PIM state")
    result = verify_pim_state(tgen, dut, oif, iif, IGMP_JOIN_V6, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "PIM state for group: {} is still Active \n Error: {}".format(
            tc_name, IGMP_JOIN_V6, result
        )
    )

    step("r1: Verify ip mroutes")
    result = verify_mroutes(tgen, dut, STAR, IGMP_JOIN_V6, oif, iif, expected=False)
    assert result is not True, (
        "Testcase {} :Failed \n "
        "mroute ({}, {}) is still present \n Error: {}".format(
            tc_name, STAR, IGMP_JOIN_V6, result
        )
    )

    step("r1: Verify show ip pim interface traffic without any IGMP join")
    state_after = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
