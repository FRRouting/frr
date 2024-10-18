#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test multicast pim6 dual stack:

1. Verify IPv4 and IPv6 mroute and upstream after removing/adding  IGMP and MLD config
2. Verify IPv4 and IPv6 mroute and upstream when IGMP and MLD join sent from different interface
   of FRR1 and source present on different interface in FRR4
3. Verify IPv4 and IPv6 mroute and upstream when IGMP and MLD join sent from same interface
   of FRR1 and source present on same interface in FRR4
4. Verify IPv4 and IPv6 mroute and upstream when mld prune is sent but igmp still runnining
    and vice-versa
5. Verify IPv4 and IPv6 mroute and upstream after removing/adding  IGMP and MLD config
"""

import os
import sys
import time
import pytest
import time
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
    step,
    reset_config_on_routers,
    shutdown_bringup_interface,
    required_linux_kernel_version,
)
from lib.pim import (
    create_pim_config,
    create_mld_config,
    verify_mld_groups,
    verify_mroutes,
    verify_upstream_iif,
    verify_pim_interface_traffic,
    verify_sg_traffic,
    McastTesterHelper,
    create_igmp_config,
    verify_igmp_groups,
    verify_pim_rp_info,
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

GROUP_RANGE_4 = [
    "226.1.1.1/32",
    "226.1.1.2/32",
    "226.1.1.3/32",
    "226.1.1.4/32",
    "226.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["226.1.1.1", "226.1.1.2", "226.1.1.3", "226.1.1.4", "226.1.1.5"]


r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r3_r4_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3
SOURCE = "Static"
ASSERT_MSG = "Testcase {} : Failed Error: {}"

pytestmark = [pytest.mark.pimd, pytest.mark.pim6d]


@pytest.fixture(scope="function")
def app_helper():
    with McastTesterHelper(get_topogen()) as ah:
        yield ah

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
    json_file = "{}/multicast_pim6_dual_stack.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    app_helper.cleanup()

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


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance, before state incremented
                        for interface traffic
    * `state_after` : State dictionary for any particular instance, after state incremented
                        for interface traffic
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


def verify_mroute_uptime(uptime_before, uptime_after):
    """
    API to compare uptime for mroutes

    Parameters
    ----------
    * `uptime_before` : Uptime dictionary for any particular instance
    * `uptime_after` : Uptime dictionary for any particular instance
    """
    for group in uptime_before.keys():
        for source in uptime_before[group].keys():
            if set(uptime_before[group]) != set(uptime_after[group]):
                errormsg = (
                    "mroute (%s, %s) has not come"
                    " up after mroute clear [FAILED!!]" % (source, group)
                )
                return errormsg

            d1 = datetime.datetime.strptime(uptime_before[group][source], "%H:%M:%S")
            d2 = datetime.datetime.strptime(uptime_after[group][source], "%H:%M:%S")
            if d1 >= d2:
                errormsg = "mroute (%s, %s) is not " "repopulated [FAILED!!]" % (
                    source,
                    group,
                )
                return errormsg

            logger.info("mroute (%s, %s) is " "repopulated [PASSED!!]", source, group)

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_ipv4_ipv6_mroute_upstream_after_removing_mld_and_igmp_config_p1(
    request, app_helper
):
    """
    Verify IPv4 and IPv6 mroute and upstream after removing/adding  IGMP and MLD config
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Enable MLD and IGMP on receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on FRR2 loopback interface for IPv4 and IPv6 group address")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            },
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            },
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) from R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IPv4 mld and IPv6 MLD join received on R1 from same interface"
        'verify using "show ipv6 mldgroups"  and "show ipv6 mld groups"'
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    step(
        "IPv4 and IPv6 (*,G) mroute and upstream created OIL"
        'and IIF updated using "show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    iif1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    iif2 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    for iif, grp_addr in zip([iif2, iif1], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):
        step("r1: Verify upstream IIF interface")
        result = verify_upstream_iif(tgen, "r1", oif, "*", grp_addr)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify ip mroutes")
        result = verify_mroutes(tgen, "r1", "*", grp_addr, oif, iif)
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "Send IPv4 and IPv6 multicast traffic from FRR4 same interface"
        "group range (FF05::1 -FF05::5 and 226.1.1.1 -226.1.1.5"
    )

    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_traffic("i8", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IPv4 and IPv6 mroute /upsteam created on FRR1 and FRR4"
        '"IIF and OIL updated using show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    source_v6 = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]

    source_v4 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].split("/")[0]

    input_dict_v4 = [
        {
            "dut": "r1",
            "src_address": source_v4,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_v4,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_v6 = [
        {
            "dut": "r4",
            "src_address": source_v6,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_v6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_v6:
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
        "IPv4 and IPv6 traffic updated per (S,G)"
        "show ipv6 multicast count ,show ip multicast count"
    )

    step("verify ipv6 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove MLD config from receiver interface")
    input_dict_1 = {
        "r1": {
            "mld": {
                "interfaces": {intf_r1_i1: {"mld": {"version": "1", "delete": True}}}
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("After removing MLD config verify IPv6 (*,G) and (S,G) removed from R1 node")
    result = verify_mroutes(
        tgen, "r1", "*", MLD_JOIN_RANGE_1, oif, iif1, expected=False
    )
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    result = verify_upstream_iif(tgen, "r1", oif, "*", MLD_JOIN_RANGE_1, expected=False)
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    for data in input_dict_v6:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed Error: {}".format(
            tc_name, result
        )

    step("verify ipv6 multicast traffic on R1 for all the grps")
    result = verify_sg_traffic(
        tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6", expected=False
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No impact on R1 IPv4 IGMP receiver")
    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on R1 for all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove IGMP config from receiver pots")
    input_dict_1 = {
        "r1": {
            "igmp": {
                "interfaces": {intf_r1_i1: {"igmp": {"version": "2", "delete": True}}}
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("After removing IGMP config verify IPv4 (*,G) and (S,G) removed from R1 node")
    result = verify_mroutes(
        tgen, "r1", "*", IGMP_JOIN_RANGE_1, oif, iif1, expected=False
    )
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    result = verify_upstream_iif(tgen, "r1", oif, "*", MLD_JOIN_RANGE_1, expected=False)
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, "Testcase {} : Failed Error: {}".format(
            tc_name, result
        )

    step("verify ipv4 multicast traffic on R1 for all the grps")
    result = verify_sg_traffic(
        tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4", expected=False
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Add IGMP and MLD config and verify mroutes and upstream")

    step("Add MLD config from receiver interface")
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Add IGMP config from receiver pots")
    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    for data in input_dict_v6:
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

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    r4_iif = (topo["routers"]["r4"]["links"]["i7"]["interface"],)
    r4_oil = topo["routers"]["r4"]["links"]["r2"]["interface"]

    step("From source node verify OIL towards RP is removed")
    result = verify_mroutes(
        tgen, "r1", source_v6, MLD_JOIN_RANGE_1, r4_iif, r4_oil, expected=False
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_mroutes(
        tgen, "r1", source_v6, IGMP_JOIN_RANGE_1, r4_iif, r4_oil, expected=False
    )
    assert result is not True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv6 multicast traffic on R1 for all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv6 multicast traffic on R1 for all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ipv4_ipv6_mroutes_upstream_when_mld_and_igmp_join_sent_from_same_interface_p0(
    request, app_helper
):
    """
    Verify IPv4 and IPv6 mroute and upstream when mld and MLD join sent from same interface
    of FRR1 and source present on same interface in FRR4
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Enable MLD on receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on receiver interface on same interface")

    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on FRR2 loopback interface for IPv4 and IPv6 group address")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            },
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            },
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify show PIM6 interface traffic without any mld join")
    intf_r1 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    state_dict = {"r1": {intf_r1: ["joinRx", "joinTx"]}}

    state_before_v6 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before_v6, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    state_before_v4 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv4")
    assert isinstance(
        state_before_v4, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("send mld join (ffaa::1-5) from R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IPv4 mld and IPv6 MLD join received on R1 from same interface"
        'verify using "show ipv6 mldgroups"  and "show ipv6 mld groups"'
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step(
        "RP got configure on all the nodes OIL and IIF is updated"
        'verify using "show ip pimv6 rp-info"'
    )

    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", MLD_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", IGMP_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "IPv4 and IPv6 (*,G) mroute and upstream created OIL"
        'and IIF updated using "show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    iif = topo["routers"]["r1"]["links"]["i1"]["interface"]
    for dut, grp_addr in zip(["r1", "r1"], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):
        step("r1: Verify upstream IIF interface")
        result = verify_upstream_iif(tgen, dut, oif, "*", grp_addr)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify ip mroutes")
        result = verify_mroutes(tgen, dut, "*", grp_addr, oif, iif)
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "Send IPv4 and IPv6 multicast traffic from FRR4 same interface"
        "group range (FF05::1 -FF05::5 and 226.1.1.1 -226.1.1.5"
    )
    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_traffic("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IPv4 and IPv6 mroute /upsteam created on FRR1 and FRR4"
        '"IIF and OIL updated using show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    source_v6 = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]

    source_v4 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].split("/")[0]

    input_dict_v4 = [
        {
            "dut": "r1",
            "src_address": source_v4,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_v4,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_v6 = [
        {
            "dut": "r4",
            "src_address": source_v6,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_v6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_v6:
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
        "IPv4 and IPv6 traffic updated per (S,G)"
        "show ipv6 multicast count ,show ip multicast count"
    )

    step("verify ipv6 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify IP pimv6 join and IPv6 pimv6 join to FRR1 and check join is sent toward FHR"
        "Join counts is increamented for both IPv4 and IPv6"
        'verify using "show ip pimv6 interface traffic" "show ipv6 pimv6 interface traffic"'
    )

    state_after_v6 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after_v6, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before_v6, state_after_v6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    state_after_v4 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv4")
    assert isinstance(
        state_after_v4, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before_v4, state_after_v4)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ipv4_ipv6_mroutes_upstream_when_mld_and_igmp_join_sent_from_different_interface_p0(
    request, app_helper
):
    """
    Verify IPv4 and IPv6 mroute and upstream when mld and MLD join sent from different interface
    of FRR1 and source present on different interface in FRR4
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Enable MLD on receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on receiver interface on same interface")
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i2: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on FRR2 loopback interface for IPv4 and IPv6 group address")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            },
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            },
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify show PIM6 interface traffic without any mld join")
    intf_r1 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    state_dict = {"r1": {intf_r1: ["joinRx", "joinTx"]}}

    state_before_v6 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before_v6, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    state_before_v4 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv4")
    assert isinstance(
        state_before_v4, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("send mld join (ffaa::1-5) from R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT for group range 225.1.1.1-5")
    input_join = {
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IPv4 mld and IPv6 MLD join received on R1 from same interface"
        'verify using "show ipv6 mldgroups"  and "show ipv6 mld groups"'
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_igmp_groups(tgen, "r1", intf_r1_i2, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step(
        "RP got configure on all the nodes OIL and IIF is updated"
        'verify using "show ip pimv6 rp-info"'
    )

    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", MLD_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", IGMP_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "IPv4 and IPv6 (*,G) mroute and upstream created OIL"
        'and IIF updated using "show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    iif1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    iif2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    for iif, grp_addr in zip([iif2, iif1], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):
        step("r1: Verify upstream IIF interface")
        result = verify_upstream_iif(tgen, "r1", oif, "*", grp_addr)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify ip mroutes")
        result = verify_mroutes(tgen, "r1", "*", grp_addr, oif, iif)
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "Send IPv4 and IPv6 multicast traffic from FRR4 same interface"
        "group range (FF05::1 -FF05::5 and 226.1.1.1 -226.1.1.5"
    )

    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_src = {"i8": topo["routers"]["i8"]["links"]["r4"]["interface"]}
    result = app_helper.run_traffic("i8", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IPv4 and IPv6 mroute /upsteam created on FRR1 and FRR4"
        '"IIF and OIL updated using show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    source_v6 = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]

    source_v4 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].split("/")[0]

    input_dict_v4 = [
        {
            "dut": "r1",
            "src_address": source_v4,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_v4,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_v6 = [
        {
            "dut": "r4",
            "src_address": source_v6,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_v6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_v6:
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
        "IPv4 and IPv6 traffic updated per (S,G)"
        "show ipv6 multicast count ,show ip multicast count"
    )

    step("verify ipv6 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify IP pimv6 join and IPv6 pimv6 join to FRR1 and check join is sent toward FHR"
        "Join counts is increamented for both IPv4 and IPv6"
        'verify using "show ip pimv6 interface traffic" "show ipv6 pimv6 interface traffic"'
    )

    state_after_v6 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after_v6, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before_v6, state_after_v6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    state_after_v4 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv4")
    assert isinstance(
        state_after_v4, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before_v4, state_after_v4)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_ipv4_ipv6_mroute_upstream_when_mld_prune_send_igmp_still_running_vica_versa_p0(
    request, app_helper
):
    """
    Verify IPv4 and IPv6 mroute and upstream when mld prune is sent but igmp still runnining
    and vice-versa
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Enable MLD on receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on receiver interface on same interface")

    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on FRR2 loopback interface for IPv4 and IPv6 group address")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            },
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            },
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) from R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT for group range 225.1.1.1-5")
    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IPv4 igmp and IPv6 MLD join received on R1 from same interface"
        'verify using "show ipv6 mldgroups"  and "show ipv6 mld groups"'
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step(
        "RP got configure on all the nodes OIL and IIF is updated"
        'verify using "show ip pimv6 rp-info"'
    )

    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", MLD_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", IGMP_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "IPv4 and IPv6 (*,G) mroute and upstream created OIL"
        'and IIF updated using "show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    iif = topo["routers"]["r1"]["links"]["i1"]["interface"]
    for dut, grp_addr in zip(["r1", "r1"], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):
        step("r1: Verify upstream IIF interface")
        result = verify_upstream_iif(tgen, dut, oif, "*", grp_addr)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify ip mroutes")
        result = verify_mroutes(tgen, dut, "*", grp_addr, oif, iif)
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "Send IPv4 and IPv6 multicast traffic from FRR4 same interface"
        "group range (FF05::1 -FF05::5 and 226.1.1.1 -226.1.1.5"
    )

    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_traffic("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IPv4 and IPv6 mroute /upsteam created on FRR1 and FRR4"
        '"IIF and OIL updated using show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    source_v6 = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]

    source_v4 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].split("/")[0]

    input_dict_v4 = [
        {
            "dut": "r1",
            "src_address": source_v4,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_v4,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_v6 = [
        {
            "dut": "r4",
            "src_address": source_v6,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_v6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_v6:
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
        "IPv4 and IPv6 traffic updated per (S,G)"
        "show ipv6 multicast count ,show ip multicast count"
    )

    step("verify ipv6  multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Kill IMGP/MLD join to send IGMP/MLD prune")
    app_helper.stop_host("i1")

    step("IPv4 mroutes and join got removed")
    result = verify_igmp_groups(
        tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n IGMP join are" " still present \n Error: {}".format(
        tc_name, result
    )
    logger.info("Expected Behavior: {}".format(result))

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n mroutes are" "still present \n Error: {}".format(
            tc_name, result
        )
        logger.info("Expected Behavior: {}".format(result))

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n upstream  are"
            " still present \n Error: {}".format(tc_name, result)
        )
        logger.info("Expected Behavior: {}".format(result))

    step("MLD join and mroutes got removed")
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n MLD join are" " still present \n Error: {}".format(
        tc_name, result
    )
    logger.info("Expected Behavior: {}".format(result))

    for data in input_dict_v6:
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
        ), "Testcase {} : Failed \n mroutes are" " still present \n Error: {}".format(
            tc_name, result
        )
        logger.info("Expected Behavior: {}".format(result))

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n upstream  are"
            " still present \n Error: {}".format(tc_name, result)
        )
        logger.info("Expected Behavior: {}".format(result))

    step("Send IGMP join and traffic again")
    result = app_helper.run_traffic("i7", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_join = {
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"],
    }
    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("send MLD join and traffic again")
    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify IPv4 and IPv6 multicast traffic resume")
    step("verify ipv6  multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify show PIM6 interface traffic without any mld join")
    intf_r1 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    state_dict = {"r1": {intf_r1: ["joinRx", "joinTx"]}}

    state_before_v6 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before_v6, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    state_before_v4 = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv4")
    assert isinstance(
        state_before_v4, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_ipv4_ipv6_mroutes_after_add_remove_ipv4_and_ipv6_RP_address_p0(
    request, app_helper
):
    """
    Verify IPv4 and IPv6 mroute and upstream when mld and MLD join sent from same interface
    of FRR1 and source present on same interface in FRR4
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    app_helper.stop_all_hosts()

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Done in base config: " "Configure EBGP peering between all the nodes")

    step("Done in base config: " "Enable PIM6 on all the interfaces of all the nodes")

    step("Enable MLD on receiver interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {
        "r1": {"mld": {"interfaces": {intf_r1_i1: {"mld": {"version": "1"}}}}}
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable IGMP on receiver interface on same interface")
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict_1 = {
        "r1": {"igmp": {"interfaces": {intf_r1_i2: {"igmp": {"version": "2"}}}}}
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on FRR2 loopback interface for IPv4 and IPv6 group address")
    input_dict = {
        "r2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_4,
                    }
                ]
            },
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                    }
                ]
            },
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) from R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send IGMP joins from DUT for group range 225.1.1.1-5")
    input_join = {
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"],
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "IPv4 mld and IPv6 MLD join received on R1 from same interface"
        'verify using "show ipv6 mldgroups"  and "show ipv6 mld groups"'
    )

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, "r1", intf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_igmp_groups(tgen, "r1", intf_r1_i2, IGMP_JOIN_RANGE_1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step(
        "RP got configure on all the nodes OIL and IIF is updated"
        'verify using "show ip pimv6 rp-info"'
    )

    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", MLD_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", IGMP_JOIN_RANGE_1, oif, rp_address, SOURCE
    )
    assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "IPv4 and IPv6 (*,G) mroute and upstream created OIL"
        'and IIF updated using "show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    iif1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    iif2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    for iif, grp_addr in zip([iif2, iif1], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):
        step("r1: Verify upstream IIF interface")
        result = verify_upstream_iif(tgen, "r1", oif, "*", grp_addr)
        assert result is True, ASSERT_MSG.format(tc_name, result)

        step("r1: Verify ip mroutes")
        result = verify_mroutes(tgen, "r1", "*", grp_addr, oif, iif)
        assert result is True, ASSERT_MSG.format(tc_name, result)

    step(
        "Send IPv4 and IPv6 multicast traffic from FRR4 same interface"
        "group range (FF05::1 -FF05::5 and 226.1.1.1 -226.1.1.5"
    )

    result = app_helper.run_traffic("i7", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_traffic("i8", IGMP_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(S,G) IPv4 and IPv6 mroute /upsteam created on FRR1 and FRR4"
        '"IIF and OIL updated using show ip mroute json" "show ipv6 mroute json"'
        '"show ip pim upstream json" "show ipv6 upstream json"'
    )

    source_v6 = topo["routers"]["i7"]["links"]["r4"]["ipv6"].split("/")[0]

    source_v4 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].split("/")[0]

    input_dict_v4 = [
        {
            "dut": "r1",
            "src_address": source_v4,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_v4,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
    ]

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_v4:
        uptime_before_v4 = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            return_uptime=True,
        )
        assert isinstance(uptime_before_v4, dict), (
            "Testcase {} : Failed \n uptime_before is not dictionary \n"
            " Error: {}".format(tc_name, result)
        )

    input_dict_v6 = [
        {
            "dut": "r4",
            "src_address": source_v6,
            "iif": topo["routers"]["r4"]["links"]["i7"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_v6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        " correct OIL and IIF on all the nodes"
    )

    for data in input_dict_v6:
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

    for data in input_dict_v6:
        uptime_before_v6 = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            return_uptime=True,
        )
        assert isinstance(uptime_before_v6, dict), (
            "Testcase {} : Failed \n uptime_before is not dictionary \n"
            " Error: {}".format(tc_name, result)
        )

    step(
        "IPv4 and IPv6 traffic updated per (S,G)"
        "show ipv6 multicast count ,show ip multicast count"
    )

    step("verify ipv6 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_v6, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify ipv4 multicast traffic on all the grps")
    result = verify_sg_traffic(tgen, "r1", IGMP_JOIN_RANGE_1, source_v4, "ipv4")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut PIMv4/v6 RP imterface from RP node")
    shutdown_bringup_interface(tgen, "r2", "lo", False)

    step("verify PIMv4 and PIMv6 RP got removed")
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", MLD_JOIN_RANGE_1, oif, rp_address, SOURCE, expected=False
    )
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv4"].split("/")[0]
    result = verify_pim_rp_info(
        tgen, topo, "r1", IGMP_JOIN_RANGE_1, oif, rp_address, SOURCE, expected=False
    )
    assert result is not True, ASSERT_MSG.format(tc_name, result)

    step("r1: Verify (*,G) mroutes got removed")
    for iif, grp_addr in zip([iif2, iif1], [IGMP_JOIN_RANGE_1, MLD_JOIN_RANGE_1]):

        result = verify_mroutes(tgen, "r1", "*", grp_addr, oif, iif, expected=False)
        assert result is not True, ASSERT_MSG.format(tc_name, result)

    step("verify (s,g) mroutes are intact")

    for data in input_dict_v6:
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

    for data in input_dict_v4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_v6:
        uptime_after_v6 = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            return_uptime=True,
        )
        assert isinstance(uptime_after_v6, dict), (
            "Testcase {} : Failed \n uptime_before is not dictionary \n"
            " Error: {}".format(tc_name, result)
        )

    for data in input_dict_v4:
        uptime_after_v4 = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            return_uptime=True,
        )
        assert isinstance(uptime_after_v4, dict), (
            "Testcase {} : Failed \n uptime_before is not dictionary \n"
            " Error: {}".format(tc_name, result)
        )

    result = verify_mroute_uptime(uptime_before_v4, uptime_after_v4)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_mroute_uptime(uptime_before_v6, uptime_after_v6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)



if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
