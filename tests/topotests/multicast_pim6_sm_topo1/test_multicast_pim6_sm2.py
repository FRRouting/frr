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
1. Verify (*,G) and (S,G) entry populated again after clear the
PIM nbr and mroute from FRR node
2. Verify SPT switchover working when RPT and SPT path is
different
"""

import sys
import time

import pytest
from lib.common_config import (
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
    create_pim_config,
    verify_mroutes,
    verify_pim_interface_traffic,
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


@pytest.fixture(scope="function")
def app_helper():
    # helper = McastTesterHelper(get_topogen())
    # yield helepr
    # helper.cleanup()
    # Even better use contextmanager functionality:
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
#
#   Testcases
#
#####################################################


def test_clear_mroute_and_verify_multicast_data_p0(request, app_helper):
    """
    Verify (*,G) and (S,G) entry populated again after clear the
    PIM nbr and mroute from FRR node
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

    step("Configure static RP on r4 for group (ffcc::1-5)")
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

    step(
        "Enable mld on FRR1 interface and send mld join ffaa::1 "
        "to ffaa::5 from different interfaces"
    )

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to all the receivers" "ffaa::1-5")

    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Clear the mroute on r1, wait for 5 sec")
    result = clear_pim6_mroute(tgen, "r1")
    assert result is True, "Testcase{}: Failed Error: {}".format(tc_name, result)

    step(
        "After clear ip mroute (*,g) entries are re-populated again"
        " with same OIL and IIF, verify using 'show ipv6 mroute' and "
        " 'show ipv6 pim upstream' "
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]
    input_dict = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
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
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 pim upstream' showing correct OIL and IIF"
        " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Clear the mroute on r3, wait for 5 sec")
    result = clear_pim6_mroute(tgen, "r3")
    assert result is True, "Testcase{}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    input_dict = [
        {
            "dut": "r3",
            "src_address": source,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"],
        }
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
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 pim upstream' showing correct OIL and IIF"
        " on all the nodes"
    )
    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Clear the mroute on r2, wait for 5 sec")
    result = clear_pim6_mroute(tgen, "r2")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    input_dict = [
        {
            "dut": "r2",
            "src_address": source,
            "iif": topo["routers"]["r2"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"],
        }
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

    step("Clear the mroute on r1, r3, wait for 5 sec")
    result = clear_pim6_mroute(tgen, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = clear_pim6_mroute(tgen, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ipv6 mroute' showing correct RPF and OIF"
        " interface for (*,G) and (S,G) entries on all the nodes"
    )

    input_dict = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
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

    step(
        "multicast traffic is resume for all the receivers using "
        " 'show ip multicast' "
    )
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_SPT_switchover_when_RPT_and_SPT_path_is_different_p0(
    request, app_helper
):
    """
    Verify SPT switchover working when RPT and SPT path is
    different
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

    step("Configure static RP for (ffcc::1-5) and " "(ffbb::1-5) in r5")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _MLD_JOIN_RANGE = MLD_JOIN_RANGE_2 + MLD_JOIN_RANGE_3

    input_dict = {
        "r5": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["r5"]["links"]["lo"]["ipv6"].split(
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

    step("send mld join (ffbb::1-5, ffcc::1-5) to R1")
    result = app_helper.run_join("i1", _MLD_JOIN_RANGE, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("registerRx and registerStopTx value before traffic sent")
    intf_r5 = topo["routers"]["r5"]["links"]["r3"]["interface"]
    state_dict = {"r5": {intf_r5: ["registerRx", "registerStopTx"]}}
    state_before = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    step(
        "Send multicast traffic from FRR3 to all the receivers" "ffbb::1-5 , ffcc::1-5"
    )
    result = app_helper.run_traffic("i2", _MLD_JOIN_RANGE, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Verify in FRR3 sending initial packet to RP using"
        " 'show ipv6 mroute' and mroute OIL is towards RP."
    )

    source = topo["routers"]["i2"]["links"]["r3"]["ipv6"].split("/")[0]

    r3_i2 = topo["routers"]["r3"]["links"]["i2"]["interface"]
    r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]

    result = verify_mroutes(tgen, "r3", source, _MLD_JOIN_RANGE, r3_i2, [r3_r5, r3_r2])
    assert result is True, "Testcase {} : " "Failed Error: {}".format(tc_name, result)

    result = verify_mroutes(tgen, "r3", source, _MLD_JOIN_RANGE, r3_i2, r3_r2)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        " After spt switchover traffic is flowing between"
        " (LHR(FRR1)-FHR(FRR3)) and (S,G) OIL is updated toward FRR1"
        " 'show mroute' and 'show pim upstream'"
    )

    input_dict = [
        {"dut": "r3", "src_address": source, "iif": r3_i2, "oil": r3_r2},
        {"dut": "r1", "src_address": source, "iif": r1_r2, "oil": r1_i1},
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

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _MLD_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic to all the receivers")
    dut = "i2"
    intf = topo["routers"]["i2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf, False)

    step(
        "Null register packet being send periodically from FRR3 to RP, "
        "verify using show ipv6 mroute on RP, have (S, G) entries null OIL"
        " 'show ipv6 mroute' and verify show ip pim interface traffic"
        "(In RP Register msg should be received and Register stop should"
        " be transmitted)"
    )

    result = verify_upstream_iif(
        tgen, "r3", "Unknown", source, _MLD_JOIN_RANGE, joinState="NotJoined"
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("registerRx and registerStopTx value after traffic sent")
    state_after = verify_pim_interface_traffic(tgen, state_dict, addr_type="ipv6")
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \n " "Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
