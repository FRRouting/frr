# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test multicast pim6 sm:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:
1. Verify Multicast data traffic with static RP, (*,g) and
(s,g) OIL updated correctly
2. Verify mroute detail when receiver is present
outside of FRR
3. Verify (*,G) and (S,G) populated correctly
when FRR is the transit router
4. Verify (S,G) should not create if RP is not reachable
5. Verify modification of mld query timer should get update
accordingly
6. Verify modification of mld max query response timer
should get update accordingly
7. Verify removing the RP should not impact the multicast
data traffic
"""

import datetime
import sys
import time

import pytest
from lib.common_config import (
    get_frr_ipv6_linklocal,
    required_linux_kernel_version,
    reset_config_on_routers,
    shutdown_bringup_interface,
    start_topology,
    step,
    write_test_footer,
    write_test_header,
)
from lib.pim import (
    McastTesterHelper,
    clear_pim6_mroute,
    create_mld_config,
    create_pim_config,
    verify_mld_config,
    verify_mld_groups,
    verify_mroute_summary,
    verify_mroutes,
    verify_pim_interface_traffic,
    verify_pim_join,
    verify_pim_nexthop,
    verify_pim_state,
    verify_sg_traffic,
    verify_upstream_iif,
)
from lib.bgp import (
    verify_bgp_convergence,
)
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

# Global variables
GROUP_RANGE = "ff00::/8"

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

HELLO_TIMER = 1
HOLD_TIMER = 3
PREFERRED_NEXT_HOP = "link_local"
ASSERT_MSG = "Testcase {} : Failed Error: {}"

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

    json_file = "multicast_pim6_sm_topo1.json"
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

    # Verify BGP convergence
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

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


def verify_mroute_repopulated(uptime_before, uptime_after):
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
            if d2 >= d1:
                errormsg = "mroute (%s, %s) is not " "repopulated [FAILED!!]" % (
                    source,
                    group,
                )
                return errormsg

            logger.info("mroute (%s, %s) is " "repopulated [PASSED!!]", source, group)

    return True


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for router, state_data in state_before.items():
        for state, _ in state_data.items():
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


def next_hop_per_address_family(
    tgen, dut, peer, addr_type, next_hop_dict, preferred_next_hop=PREFERRED_NEXT_HOP
):
    """
    This function returns link_local or global next_hop per address-family
    """

    intferface = topo["routers"][peer]["links"]["{}".format(dut)]["interface"]
    if addr_type == "ipv6" and "link_local" in preferred_next_hop:
        next_hop = get_frr_ipv6_linklocal(tgen, peer, intf=intferface)
    else:
        next_hop = next_hop_dict[addr_type]

    return next_hop


#####################################################
#
#   Testcases
#
#####################################################


def test_multicast_data_traffic_static_RP_send_traffic_then_join_p0(request):
    """
    Verify Multicast data traffic with static RP, (*,g) and
    (s,g) OIL updated correctly
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("shut R1 to R4 and R3 to R5 link  to simulate test topology")
    r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]

    shutdown_bringup_interface(tgen, "r1", r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", r3_r5, False)

    step(
        "Configure RP as R2 (loopback interface) for the"
        " group range ff00::/8 on all the routers"
    )

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Start traffic first and then send the mld join")

    step("Send multicast traffic from FRR3 to all the receivers" "ffaa::1-5")

    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]

    step("verify upstream in NOT join Rej prune state on R3")

    input_dict_sg = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        }
    ]

    for data in input_dict_sg:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            joinState="NotJoined",
            regState="RegPrune",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("joinRx value before join sent")
    r2_r1_intf = topo["routers"]["r2"]["links"]["r1"]["interface"]
    state_dict = {"r2": {r2_r1_intf: ["joinRx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    input_dict = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r2",
            "src_address": source,
            "iif": topo["routers"]["r2"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        },
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 pim upstream' showing correct OIL and IIF"
        " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify join state is joined")
    for data in input_dict_sg:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            joinState="Joined",
            regState="RegPrune",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("joinRx value after join sent")
    state_after = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step(
        "r1 sent PIM (*,G) join to r2 verify using"
        "'show ipv6 pim interface traffic' on RP connected interface"
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("r1 sent PIM (S,G) join to r3 , verify using 'show ipv6 pim join'")
    dut = "r3"
    interface = topo["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_pim_join(tgen, topo, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    _nexthop = topo["routers"]["r1"]["links"]["r2"]["ipv6"].split("/")[0]
    next_hop = next_hop_per_address_family(tgen, "r1", "r2", "ipv6", _nexthop)

    step("verify nexthop on r3 using 'show ipv6 pim nexthop'")
    result = verify_pim_nexthop(tgen, topo, "r1", next_hop, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify mroute summary on r1 using 'show ipv6 mroute summary json'")
    result = verify_mroute_summary(
        tgen, "r1", sg_mroute=5, starg_mroute=5, total_mroute=10, addr_type="ipv6"
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_receiver_is_outside_frr_p0(request):
    """
    Verify mroute detail when receiver is present
    outside of FRR
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure static RP on r4 for group range " "(ffcc::1-5) and (ffbb::1-5)")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _MLD_JOIN_RANGE = MLD_JOIN_RANGE_2 + MLD_JOIN_RANGE_3

    input_dict = {
        "r4": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r4"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": _GROUP_RANGE,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", _MLD_JOIN_RANGE, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify MLD joins received on r1")
    dut = "r1"
    interface = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, dut, interface, _MLD_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to all the receivers" "ffaa::1-5")
    result = app_helper.run_traffic("i2", _MLD_JOIN_RANGE, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Configure one more receiver in r5 enable mld and send"
        " join (ffaa::1-5) and (ffbb::1-5)"
    )
    r5_i5 = topo["routers"]["r5"]["links"]["i5"]["interface"]

    input_dict = {"r5": {"mld": {"interfaces": {r5_i5: {"mld": {"version": "1"}}}}}}
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i5", _MLD_JOIN_RANGE, "r5")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("FRR1 has 10 (*.G) and 10 (S,G) verify using 'show ipv6 mroute'")
    step(
        "All the receiver are receiving traffic on FRR1 and (S,G) OIL is towards"
        "receivers, verify using 'show mroute' 'show  pim upstream'"
    )
    step(
        "All the receiver are receiving traffic on r5 and (S,G) OIL is "
        "toward receivers, verify using 'show ipv6 mroute' 'show ipv6 pim upstream'"
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": "*",
            "iif": topo["routers"]["r5"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r5"]["links"]["i5"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": source,
            "iif": topo["routers"]["r5"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r5"]["links"]["i5"]["interface"],
        },
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _MLD_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "FRR3 has (S,G) OIL created toward r2/r5 receiver and FRR1 receiver"
        "'show ipv6 pim '"
    )
    input_dict = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r5"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        },
    ]
    for data in input_dict:
        result = verify_pim_state(
            tgen,
            data["dut"],
            data["iif"],
            data["oil"],
            _MLD_JOIN_RANGE,
            data["src_address"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            _MLD_JOIN_RANGE,
            joinState="Joined",
            regState="RegPrune",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Traffic is received fine on FRR1 and r5 " " 'show ipv6 mroute count' ")

    result = verify_sg_traffic(tgen, "r1", _MLD_JOIN_RANGE, source, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = verify_sg_traffic(tgen, "r5", _MLD_JOIN_RANGE, source, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_frr_is_transit_router_p2(request):
    """
    Verify (*,G) and (S,G) populated correctly
    when FRR is the transit router
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure static RP for (ffaa::1-5) in r5")
    input_dict = {
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
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Enable mld on FRR1 interface and send mld join ")

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify mld groups received on R1")
    dut = "r1"
    interface = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to ffaa::1-5 receivers")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("shut the direct link to R1 ")
    intf = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "FRR4 has (S,G) and (*,G) ,created where incoming interface"
        " toward FRR3 and OIL toward R2, verify using 'show ipv6 mroute'"
        " 'show ipv6 pim state' "
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict = [
        {
            "dut": "r5",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
        {
            "dut": "r5",
            "src_address": source,
            "iif": topo["routers"]["r5"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify multicast traffic")
    result = verify_sg_traffic(tgen, "r5", MLD_JOIN_RANGE_1, source, "ipv6")
    assert (
        result is True
    ), "Testcase {} : Failed \n mroutes traffic " "still present \n Error: {}".format(
        tc_name, result
    )

    step("Stop multicast traffic from FRR3")
    dut = "i2"
    intf = topo["routers"]["i2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("(*,G) present on R5 after source shut")

    input_dict_1 = [
        {
            "dut": "r5",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r5"]["links"]["r4"]["interface"],
        },
    ]
    for data in input_dict_1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("stop mld receiver from FRR1")
    dut = "i1"
    intf = topo["routers"]["i1"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "After stopping receiver (*, G) and (S, G) also got removed from transit"
        " router 'show ipv6 mroute'"
    )

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n mroutes "
            "not removed after removing the receivers \n Error: {}".format(
                tc_name, result
            )
        )

    logger.info("Expected Behavior: {}".format(result))

    write_test_footer(tc_name)


def test_verify_mroute_when_RP_unreachable_p1(request):
    """
    Verify (S,G) should not create if RP is not reachable
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure RP on FRR2 (loopback interface) for " "the group range ffaa::1-5")

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Enable mld on FRR1 interface and send mld join ffaa::1-5")

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to ffaa::1-5 receivers")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure one MLD interface on FRR3 node and send MLD" " join (ffcc::1)")
    r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict = {"r3": {"mld": {"interfaces": {r3_i8: {"mld": {"version": "1"}}}}}}
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify MLD groups received ")
    dut = "r3"
    interface = topo["routers"]["r3"]["links"]["i8"]["interface"]
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict = [
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"],
        },
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the RP connected interface from r3 ( r2 to r3) link")
    dut = "r3"
    intf = topo["routers"]["r3"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step("Clear the mroute on r3")
    clear_pim6_mroute(tgen, "r3")

    step(
        "After Shut the RP interface and clear the mroute verify all "
        "(*,G) and (S,G) got timeout from FRR3 node , verify using "
        " 'show ipv6 mroute' "
    )
    r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]

    result = verify_mroutes(
        tgen, "r3", "*", MLD_JOIN_RANGE_1, r3_r2, r3_i8, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n mroutes are" " still present \n Error: {}".format(
        tc_name, result
    )
    logger.info("Expected Behavior: {}".format(result))

    step("mld groups are present verify using 'show ip mld group'")
    dut = "r1"
    interface = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_modify_mld_query_timer_p0(request):
    """
    Verify modification of mld query timer should get update
    accordingly
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable MLD on receiver interface")
    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict_1 = {
        "r3": {"mld": {"interfaces": {intf_r3_i8: {"mld": {"version": "1"}}}}}
    }

    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify MLD groups received ")
    dut = "r3"
    interface = topo["routers"]["r3"]["links"]["i8"]["interface"]
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for the" " group range ffaa::1-5")

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send multicast traffic from FRR3 to ffaa::1-5 receivers")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict_4 = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"],
        },
    ]
    for data in input_dict_4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            mwait=20,
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 pim upstream' showing correct OIL and IIF"
        " on all the nodes"
    )
    for data in input_dict_4:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Modify mld query interval default to other timer on FRR1" ", 3 times")

    input_dict_1 = {
        "r3": {
            "mld": {
                "interfaces": {intf_r3_i8: {"mld": {"query": {"query-interval": 100}}}}
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_2 = {
        "r3": {
            "mld": {
                "interfaces": {intf_r3_i8: {"mld": {"query": {"query-interval": 200}}}}
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r3": {
            "mld": {
                "interfaces": {intf_r3_i8: {"mld": {"query": {"query-interval": 300}}}}
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {"query": {"query-interval": 300, "delete": True}}
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("veriffy mroutes after query modification")
    for data in input_dict_4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            mwait=20,
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_modify_mld_max_query_response_timer_p0(request):
    """
    Verify modification of mld max query response timer
    should get update accordingly
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable mld on FRR1 interface and send MLD join")
    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    step("Configure mld query response time to 10 sec on FRR1")
    input_dict_1 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 10},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP on R2 (loopback interface) for the" " group range 225.0.0.0/8")

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Send multicast traffic from FRR3 to ffaa::1-5 receivers")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict_5 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        },
    ]
    for data in input_dict_5:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            mwait=20,
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 pim upstream' showing correct OIL and IIF"
        " on all the nodes"
    )
    for data in input_dict_5:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete the PIM and mld on FRR1")
    r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 = {"r1": {"pim6": {"disable": [r1_i1]}}}
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_2 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "delete": True,
                            "query": {"query-max-response-time": 10, "delete": True},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure PIM on FRR")
    result = create_pim_config(tgen, topo["routers"])
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure max query response timer 100sec on FRR1")
    input_dict_3 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 100},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Remove and add max query response timer cli with different"
        "timer 5 times on FRR1 Enable mld and mld version 2 on FRR1"
        " on FRR1"
    )

    input_dict_3 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 110},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 120},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 140},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r1": {
            "mld": {
                "interfaces": {
                    r1_i1: {
                        "mld": {
                            "version": "1",
                            "query": {"query-max-response-time": 150},
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Enable mld and mld version 2 on FRR1 on FRR1")

    input_dict_4 = {"r1": {"mld": {"interfaces": {r1_i1: {"mld": {"version": "1"}}}}}}
    result = create_mld_config(tgen, topo, input_dict_4)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_impact_on_multicast_traffic_when_RP_removed_p0(request):
    """
    Verify removing the RP should not impact the multicast
    data traffic
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("send multicast traffic for group range ffaa::1-5")

    step("Send multicast traffic from FRR3 to ffaa::1-5 receivers")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for group (ffaa::1) on r5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
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

    step("Enable mld on FRR1 interface and send MLD join")
    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "After SPT switchover traffic is flowing (FRR3-FRR2-FRR1)"
        " and (s,g) OIL updated correctly using 'show ipv6 mroute'"
        " 'show ipv6 pim upstream'"
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    for data in input_dict:
        if data["dut"] == "r1":
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

    for data in input_dict:
        if data["dut"] == "r3":
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

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut RP interface in r5")
    dut = "r5"
    intf = "lo"
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "After no shut of RP verify (*,G) entries re-populated again"
        " and uptime go reset verify using 'show ipv6 mroute'"
        " 'show ipv6 pim state'"
    )

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Remove static RP for group (ffaa::1) on r5")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r2"]["links"]["lo"]["ipv6"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_1,
                        "delete": True,
                    }
                ]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("After remove of RP verify no impact on (s,g)")

    input_dict = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("verify multicast traffic is flowing")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
