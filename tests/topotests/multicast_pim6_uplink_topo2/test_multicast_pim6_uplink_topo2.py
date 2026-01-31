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
Following tests are covered to test multicast pim6 uplink:

1. Verify changing RP address on DUT from Static to BSR , IIF and OIF
updated correctly
2. Verify when mroute RPT and SPT path is difference
3. Verify mroutes updated with correct OIL and IIF after shut / no shut of
upstream interface from DUT
4. Verify mroutes updated with correct OIL and IIF after shut / no
shut of downstream interface from FHR
"""

import os
import re
import sys
import json
import time
import pytest

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
    step,
    reset_config_on_routers,
    shutdown_bringup_interface,
    required_linux_kernel_version,
    topo_daemons,
    socat_send_mld_join,
    socat_send_pim6_traffic,
    kill_socat,
)
from lib.bgp import create_router_bgp
from lib.pim import (
    create_pim_config,
    create_mld_config,
    verify_mld_groups,
    verify_mroutes,
    clear_pim6_interface_traffic,
    verify_upstream_iif,
    clear_pim6_mroute,
    verify_multicast_traffic,
    verify_pim_rp_info,
    verify_pim_interface_traffic,
    verify_pim_state,
    verify_sg_traffic,
    verify_pim6_neighbors,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

# Global variables
GROUP_RANGE_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
MLD_JOIN_RANGE_1 = ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]
GROUP_RANGE_2 = [
    "ffbb::1/128",
    "ffbb::2/128",
    "ffbb::3/128",
    "ffbb::4/128",
    "ffbb::5/128",
]
MLD_JOIN_RANGE_2 = ["ffbb::1", "ffbb::2", "ffbb::3", "ffbb::4", "ffbb::5"]
GROUP_RANGE_3 = [
    "ffcc::1/128",
    "ffcc::2/128",
    "ffcc::3/128",
    "ffcc::4/128",
    "ffcc::5/128",
]
MLD_JOIN_RANGE_3 = ["ffcc::1", "ffcc::2", "ffcc::3", "ffcc::4", "ffcc::5"]

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []

pytestmark = [pytest.mark.pim6d]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim6_uplink_topo2.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, tgen.json_topo)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen, daemons)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

    # Pre-requisite data
    get_interfaces_names(topo)

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
#
#   Local APIs
#
#####################################################


def get_interfaces_names(topo):
    """
    API to fetch interfaces names and create list, which further would be used
    for verification

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for link in range(1, 5):

        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(link)]["interface"]
        r1_r2_links.append(intf)

        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(link)]["interface"]
        r1_r3_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r1-link{}".format(link)]["interface"]
        r2_r1_links.append(intf)

        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(link)]["interface"]
        r3_r1_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r4-link{}".format(link)]["interface"]
        r2_r4_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(link)]["interface"]
        r4_r2_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(link)]["interface"]
        r4_r3_links.append(intf)


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
            if state_before[router][state] > state_after[router][state]:
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
#
#   Testcases
#
#####################################################


def test_pim6_iif_oil_when_RP_address_changes_from_static_to_BSR_p1(request):
    """
    Verify changing RP address on DUT from Static to BSR , IIF and OIF
    updated correctly
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown interfaces which are not required")
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r1_r5 = topo["routers"]["r1"]["links"]["r5"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_r5_r1 = topo["routers"]["r5"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r1", intf_r1_r5, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r1, False)

    step("Enable MLD on DUT and R4 interface")
    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r2", "r4"], [intf_r2_i3, intf_r4_i7]):
        input_dict = {dut: {"mld": {"interfaces": {intf: {"mld": {"version": "1"}}}}}}

        result = create_mld_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send MLD joins from DUT, and R4 for group range ffaa::1-5")
    step("i3: send mld join (ffaa::1-5) to R2")
    intf = topo["routers"]["i3"]["links"]["r2"]["interface"]
    intf_ip = topo["routers"]["i3"]["links"]["r2"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i3", "UDP6-RECV", MLD_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i7: send mld join (ffaa::1-5) to R4")
    intf = topo["routers"]["i7"]["links"]["r4"]["interface"]
    intf_ip = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i7", "UDP6-RECV", MLD_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP as R4 loopback interface for group range ffaa::1-5")
    input_dict = {
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from DUT for group range ffaa::1-5")

    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i2: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i2"]["links"]["r1"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i2", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF and OIL updated on both the nodes")

    step(
        "(S,G) IIF updated towards shortest path to source on both the nodes "
        ", verify using 'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    source_i4 = topo["routers"]["i4"]["links"]["r2"]["ipv6"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r2",
            "src_address": "*",
            "iif": r2_r4_links,
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": "lo",
            "oil": r4_r2_links + [topo["routers"]["r4"]["links"]["i7"]["interface"]],
        },
        {
            "dut": "r2",
            "src_address": source_i6,
            "iif": r2_r4_links,
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source_i4,
            "iif": topo["routers"]["r2"]["links"]["i4"]["interface"],
            "oil": r2_r4_links + [topo["routers"]["r2"]["links"]["i3"]["interface"]],
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links + [topo["routers"]["r4"]["links"]["i7"]["interface"]],
        },
        {
            "dut": "r4",
            "src_address": source_i4,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "OIL is updated and traffic is received for all the groups on both "
        "the nodes , verify using 'show ipv6 multicast'; 'show ipv6 multicast json'"
    )

    for dut, src in zip(["r1", "r4"], [source_i4, source_i6]):
        result = verify_sg_traffic(tgen, dut, MLD_JOIN_RANGE_1, src, "ipv6")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Change RP address for range ffaa::1-5 to cisco (BSRP) " "loopback interface")
    input_dict = {
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        },
        "r5": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r5"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send one more traffic stream from R4 to group range ffaa::1-5")

    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("RP type is changed to BSRP for ffaa::1-5 groups range on DUT")

    rp_addr = topo["routers"]["r5"]["links"]["lo"]["ipv6"].split("/")[0]

    result = verify_pim_rp_info(
        tgen, topo, "r5", GROUP_RANGE_1, "lo", rp_addr, "Static"
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "No impact seen on multicast data traffic for both groups range "
        "verify using 'show ipv6 multicast json' and 'show ipv6 mroute json'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                MLD_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    for dut, src in zip(["r1", "r4"], [source_i4, source_i6]):
        result = verify_sg_traffic(tgen, dut, MLD_JOIN_RANGE_1, src, "ipv6")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Stop traffic and do clear mroute on all the node (make "
        "sure (s,g) got timeout"
    )

    kill_socat(tgen, "i6", action="remove_mld_traffic")
    kill_socat(tgen, "i4", action="remove_mld_traffic")
    clear_pim6_mroute(tgen)

    step("Verify (S,G) got cleared after stop of traffic and 'clear mroute'")

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed " "Mroutes are still present \n Error: {}".format(
            tc_name, result
        )

    step("Send traffic again to from both the sources")

    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i4: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i4"]["links"]["r2"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i4", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After starting traffic DUT has created (S,G) for local and R4 "
        "source 'show ipv6 mroute'"
    )
    step(
        "DUT has OIL (S,G) OIL for local receivers and toward R1 receivers "
        "and tOIL towards RP got timeout within 60sec of traffic start "
        "'show ipv6 mroute'"
    )

    for data in input_dict_star_sg:
        if data["src_address"] != "*":
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                MLD_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_pim6_mroute_when_RPT_and_SPT_path_is_different_p1(request):
    """
    Verify when mroute RPT and SPT path is difference
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shut link from R3 to R1 and no shut R1 to R4 link to make star topology")
    for i in range(1, 5):
        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, False)

        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    intf_r4_r5 = topo["routers"]["r4"]["links"]["r5"]["interface"]
    intf_r5_r4 = topo["routers"]["r5"]["links"]["r4"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r1_r5 = topo["routers"]["r1"]["links"]["r5"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_r5_r1 = topo["routers"]["r5"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r4, False)
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, True)
    shutdown_bringup_interface(tgen, "r1", intf_r1_r5, True)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, True)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r1, True)

    step("Done in base config: Connected one more route R5 before R1 ( R5-R1)")

    step("Enable MLD on R5 and R4 interface")
    intf_r5_i8 = topo["routers"]["r5"]["links"]["i8"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    for dut, intf in zip(["r4", "r5"], [intf_r4_i7, intf_r5_i8]):
        input_dict = {dut: {"mld": {"interfaces": {intf: {"mld": {"version": "2"}}}}}}

        result = create_mld_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send MLD joins from R5, for group range ffbb::1-5")
    step("i7: send mld join (ffaa::1-5) to R4")
    intf = topo["routers"]["i7"]["links"]["r4"]["interface"]
    intf_ip = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i7", "UDP6-RECV", MLD_JOIN_RANGE_2, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("i8: send mld join (ffaa::1-5) to R5")
    intf = topo["routers"]["i8"]["links"]["r5"]["interface"]
    intf_ip = topo["routers"]["i8"]["links"]["r5"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i8", "UDP6-RECV", MLD_JOIN_RANGE_2, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range ffbb::1-5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R3 for group range ffbb::1-5")

    step("i5: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i5"]["links"]["r3"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i5", "UDP6-SEND", MLD_JOIN_RANGE_2, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("(*,G) IIF updated for ffaa::1-5 towards R2 and RP " "type is static on DUT")

    step("(S,G) on R5 has updated for all the groups")

    source_i5 = topo["routers"]["i5"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict_star_sg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["r5"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": "*",
            "iif": r4_r2_links + [intf_r4_r1],
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i5,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r5"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_i5,
            "iif": r4_r2_links + r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"],
        },
    ]

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) on R1 updated and has IIF toward R4 and OIL toward R5 , "
        "RP path OIL is removed"
    )

    source_i5 = topo["routers"]["i5"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {"dut": "r1", "src_address": source_i5, "iif": r1_r2_links, "oil": r1_r2_links},
        {"dut": "r4", "src_address": source_i5, "iif": r4_r2_links, "oil": r4_r2_links},
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed " "OIF and IIF are same \n Error: {}".format(
            tc_name, result
        )

    step("Shut and no Shut of mroute OIL selected links from R1 towards R2 and R4")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After shut and no shut of link verify mroute got populated as per "
        "verification step 8"
    )

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed " "OIF and IIF are same \n Error: {}".format(
            tc_name, result
        )

    step("Shut and no Shut of mroute OIL selected links from R4 towards R2 and R1")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

    step(
        "After shut and no shut of link verify mroute got populated as per "
        "verification step 8"
    )

    for data in input_dict_star_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed " "OIF and IIF are same \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_with_correct_oil_iif_after_shut_noshut_upstream_interface_p0(
    request,
):
    """
    Verify mroutes updated with correct OIL and IIF after shut / no shut of
    upstream interface from DUT
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown interfaces which are not required")
    intf_r1_r5 = topo["routers"]["r1"]["links"]["r5"]["interface"]
    intf_r5_r1 = topo["routers"]["r5"]["links"]["r1"]["interface"]
    intf_r4_r5 = topo["routers"]["r4"]["links"]["r5"]["interface"]
    intf_r5_r4 = topo["routers"]["r5"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r1, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r4, False)

    step("Enable MLD on DUT receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    for dut, intf in zip(["r1", "r1"], [intf_r1_i1, intf_r1_i2]):
        input_dict = {dut: {"mld": {"interfaces": {intf: {"mld": {"version": "1"}}}}}}

        result = create_mld_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify pim interface traffic before sending join/traffic")

    intf_traffic = topo["routers"]["r4"]["links"]["r3-link1"]["interface"]
    state_dict = {"r4": {intf_traffic: ["registerStopRx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, state_before
    )

    step("Send MLD joins from DUT for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i1", "UDP6-RECV", MLD_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 and R3 interface (faa::1-3 on R2 and " "faa::4-5 on R3)")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[0:3],
                    }
                ]
            }
        },
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[3:5],
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("Done in base config: " "Configure BGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range ffaa::1-5")

    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) IIF is updated DUT-R2 any one interface for groups ffaa::1-3 "
        "and DUT to R3 any one interface for groups ffaa::1-3"
    )

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links,
            "iif_r1_r3": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r2"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source verify using "
        "'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) and (S,G) OIL is updated and traffic is received for all "
        "the groups verify using 'show ipv6 multicast' and"
        "'show ipv6 multicast count json'"
    )

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Register packets sent/received count is incrementing verify "
        "using 'show ipv6 pim interface traffic json'"
    )

    state_after = verify_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Shut interface connected from R4 to DUT")
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    step(
        "After shut of R4 to DUT interface verify (S,G) has taken "
        "different path ( via R2 or R3 any link) , uptime got resetted "
        "and OIL is updated accordingly No impact seen on (*,G) routes , "
        "verify uptime for (*,G) using 'show ipv6 mroute json' and "
        "'show ipv6 pim state'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r2"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the interface connected from DUT to R2 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of DUT to R2 all the interfaces (S,G) created via R3, "
        "(S,G) uptime get reset and OIL is updated accordingly, No impact "
        "seen on (*,G) routes verify using 'show ipv6 mroute json'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the interface connected from DUT to R3 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)

    step(
        "After shut of DUT to R3 all the interfaces (S,G) got cleared "
        "from all the node, No impact seen on (*,G) routes verify using "
        "'show ipv6 mroute json'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n morutes are still " "present Error: {}".format(
            tc_name, result
        )

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n morutes are still " "present Error: {}".format(
            tc_name, result
        )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n morutes are still " "present Error: {}".format(
            tc_name, result
        )

    step("No shut the interface connected from DUT to R3 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After No shut of DUT to R3 interface, verify (S,G) got created "
        "on DUT with R3 path IIF and OIL verify using 'show ipv6 mroute json' "
        " and 'show ipv6 pim upstream json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the interface connected from DUT to R2 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)

    step(
        "After No shut of DUT to R2 interface ,verify No impact seen on "
        "(S,G) mroutes , (*,G) mroute 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the interface connected from DUT to R4")

    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, True)

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links,
            "iif_r1_r3": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source verify using "
        "'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_pim6_mroutes_updated_with_correct_oil_iif_after_shut_noshut_downstream_interface_p0(
    request,
):
    """
    Verify mroutes updated with correct OIL and IIF after shut / no
    shut of downstream interface from FHR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_pim6_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim6_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown interfaces which are not required")
    intf_r1_r5 = topo["routers"]["r1"]["links"]["r5"]["interface"]
    intf_r5_r1 = topo["routers"]["r5"]["links"]["r1"]["interface"]
    intf_r4_r5 = topo["routers"]["r4"]["links"]["r5"]["interface"]
    intf_r5_r4 = topo["routers"]["r5"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r1, False)
    shutdown_bringup_interface(tgen, "r4", intf_r4_r5, False)
    shutdown_bringup_interface(tgen, "r5", intf_r5_r4, False)

    step("Enable MLD on DUT receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    for dut, intf in zip(["r1", "r1"], [intf_r1_i1, intf_r1_i2]):
        input_dict = {dut: {"mld": {"interfaces": {intf: {"mld": {"version": "1"}}}}}}

        result = create_mld_config(tgen, topo, input_dict)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send MLD joins from DUT for group range ffaa::1-5")
    step("i1: send mld join (ffaa::1-5) to R1")
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_ip = topo["routers"]["i1"]["links"]["r1"]["ipv6"].split("/")[0]
    result = socat_send_mld_join(
        tgen, "i1", "UDP6-RECV", MLD_JOIN_RANGE_1, intf, intf_ip
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 and R3 interface (faa::1-3 on R2 and " "faa::4-5 on R3)")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[0:3],
                    }
                ]
            }
        },
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[3:5],
                    }
                ]
            }
        },
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Done in base config: " "Configure BGP peering between all the nodes")

    step("Done in base config: " "Enable PIM on all the interfaces of all the nodes")

    step("Send traffic from R4 for group range ffaa::1-5")

    step("i6: Send multicast traffic for group ffaa::1-5")
    intf = topo["routers"]["i6"]["links"]["r4"]["interface"]
    result = socat_send_pim6_traffic(tgen, "i6", "UDP6-SEND", MLD_JOIN_RANGE_1, intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) IIF is updated DUT-R2 any one interface for groups ffaa::1-3 "
        "and DUT to R3 any one interface for groups ffaa::1-3"
    )

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links,
            "iif_r1_r3": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r2"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source verify using "
        "'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) and (S,G) OIL is updated and traffic is received for all "
        "the groups verify using 'show ipv6 multicast' and"
        "'show ipv6 multicast count json'"
    )

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut interface connected from R4 to DUT")
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, False)

    step(
        "After shut of R4 to DUT interface verify (S,G) has taken "
        "different path ( via R2 or R3 any link) , uptime got resetted "
        "and OIL is updated accordingly No impact seen on (*,G) routes , "
        "verify uptime for (*,G) using 'show ipv6 mroute json' and "
        "'show ipv6 pim state'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r2"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the interface connected from R4 to R2 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step(
        "After shut of R4 to R2 all the interfaces (S,G) created via R3, "
        "(S,G) uptime get reset and OIL is updated accordingly, No impact "
        "seen on (*,G) routes verify using 'show ipv6 mroute json'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r2"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif_r1_r3"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the interface connected from R4 to R3 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step(
        "After shut of R4 to R3 all the interfaces (S,G) got cleared "
        "from all the node, No impact seen on (*,G) routes verify using "
        "'show ipv6 mroute json'"
    )

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n morutes are still " "present Error: {}".format(
            tc_name, result
        )

    step("No shut the interface connected from R4 to R3 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

    step(
        "After No shut of R4 to R3 interface, verify (S,G) got created "
        "on DUT with R3 path IIF and OIL verify using 'show ipv6 mroute json' "
        " and 'show ipv6 pim upstream json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the interface connected from R4 to R2 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    step(
        "After No shut of R4 to R2 interface ,verify No impact seen on "
        "(S,G) mroutes , (*,G) mroute 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links + r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the interface connected from R4 to DUT")

    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, True)

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IIF updated towards shortest path to source verify using "
        "'show ipv6 mroute' and 'show ipv6 mroute json'"
    )

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv6"].split("/")[0]
    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Reverse candidate RP by making (ffaa::1-3 on R3 and ffaa::4-5 on R2)")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[0:3],
                        "delete": True,
                    },
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[3:5],
                    },
                ]
            }
        },
        "r3": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[3:5],
                        "delete": True,
                    },
                    {
                        "rp_addr": topo["routers"]["r3"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1[0:3],
                    },
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("OIL and IIF for (*,G) is updated as per new RP outgoing interface")

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif_r1_r2": r1_r2_links,
            "iif_r1_r3": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_starg:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[3:5],
            data["iif_r1_r2"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1[0:3],
            data["iif_r1_r3"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
