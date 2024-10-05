#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test multicast pim sm:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:
1. TC_17: Verify (*,G) and (S,G) present and multicast traffic resume,
    after restart of PIMd daemon
2. TC_18: Verify (*,G) and (S,G) present and multicast traffic resume after
    FRR service stop and start
3. TC_10: Verify SPT switchover working when RPT and SPT path is
    different
4. TC_15: Verify (S,G) and (*,G) mroute after shut / no shut of upstream
    interfaces
5. TC_7: Verify mroute detail when receiver is present
    outside of FRR
6. TC_8: Verify mroute when FRR is acting as FHR and LHR
7. TC_20: Verify mroute detail when 5 different receiver joining
    same source
8. TC_22: Verify OIL and IIF detail updated in (S,G) mroute after shut
    and no shut of the source interface
"""

import os
import sys
import time
import pytest

pytestmark = [pytest.mark.pimd]

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
    kill_router_daemons,
    start_router,
    start_router_daemons,
    stop_router,
    required_linux_kernel_version,
)
from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    get_pim_interface_traffic,
    verify_upstream_iif,
    verify_pim_neighbors,
    verify_pim_state,
    clear_mroute,
    clear_pim_interface_traffic,
    McastTesterHelper,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json


TOPOLOGY = """


    i4-----c1-------------c2---i5
            |              |
            |              |
    i1-----l1------r2-----f1---i2
       |    |      |       |
       |    |      |       |
      i7    i6     i3     i8

    Description:
    i1, i2, i3. i4, i5, i6, i7, i8 - FRR running iperf to send IGMP
                                     join and traffic
    l1 - LHR
    f1 - FHR
    r2 - FRR router
    c1 - FRR router
    c2 - FRR router
"""

# Global variables
GROUP_RANGE = "225.0.0.0/8"
IGMP_JOIN = "225.1.1.1"
GROUP_RANGE_1 = [
    "225.1.1.1/32",
    "225.1.1.2/32",
    "225.1.1.3/32",
    "225.1.1.4/32",
    "225.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["225.1.1.1", "225.1.1.2", "225.1.1.3", "225.1.1.4", "225.1.1.5"]
GROUP_RANGE_2 = [
    "226.1.1.1/32",
    "226.1.1.2/32",
    "226.1.1.3/32",
    "226.1.1.4/32",
    "226.1.1.5/32",
]
IGMP_JOIN_RANGE_2 = ["226.1.1.1", "226.1.1.2", "226.1.1.3", "226.1.1.4", "226.1.1.5"]

GROUP_RANGE_3 = [
    "227.1.1.1/32",
    "227.1.1.2/32",
    "227.1.1.3/32",
    "227.1.1.4/32",
    "227.1.1.5/32",
]
IGMP_JOIN_RANGE_3 = ["227.1.1.1", "227.1.1.2", "227.1.1.3", "227.1.1.4", "227.1.1.5"]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel version should be >= 4.19")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    json_file = "{}/multicast_pim_sm_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
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


def test_verify_mroute_and_traffic_when_pimd_restarted_p2(request):
    """
    TC_17: Verify (*,G) and (S,G) present and multicast traffic resume,
    after restart of PIMd daemon
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c1")
    step("Configure static RP for (232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        },
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Enable IGMP on FRR1 interface and send IGMP join "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )
    step(
        "Configure IGMP interface on FRR3 and send IGMP join"
        " for group (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i1": "i1-l1-eth0", "i8": "i8-f1-eth0"}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Connect one source to c2 and send multicast traffic all"
        " the receivers (226.1.1.1-5, 232.1.1.1-5)"
    )
    step(
        "Send multicast traffic from FRR3 to all the receivers "
        "(226.1.1.1-5, 232.1.1.1-5)"
    )

    input_src = {"i2": "i2-f1-eth0", "i5": "i5-c2-eth0"}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Verifying mroutes before PIMd restart, fetching uptime

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Restart Pimd process on FRR3 node")
    kill_router_daemons(tgen, "f1", ["pimd"])
    start_router_daemons(tgen, "f1", ["pimd"])

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After restart of PIMd verify pim nbr is up , IGMP groups"
        " received , and (*,G) (S,G) entries populated again ,"
        " Verify using 'show ip pim neighbor' , 'show ip igmp groups'"
        " 'show ip mroute'"
    )

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dut = "f1"
    interface = "f1-i8-eth2"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic and restart PIMd immediately on FRR3 node")
    dut = "i2"
    intf = "i2-f1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    kill_router_daemons(tgen, "f1", ["pimd"])
    start_router_daemons(tgen, "f1", ["pimd"])

    step(
        "After PIM process come , all the none of (S,G) mroute should"
        " present on FRR3 'show ip mroute' "
    )

    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict = [
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "none"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    write_test_footer(tc_name)


def test_verify_mroute_and_traffic_when_frr_restarted_p2(request):
    """
    TC_18: Verify (*,G) and (S,G) present and multicast traffic resume after
    FRR service stop and start
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c1")
    step("Configure static RP for (232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        },
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Enable IGMP on FRR1 interface and send IGMP join "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )
    step(
        "Configure IGMP interface on FRR3 and send IGMP join"
        " for group (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i1": "i1-l1-eth0", "i8": "i8-f1-eth0"}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Connect one source to c2 and send multicast traffic all"
        " the receivers (226.1.1.1-5, 232.1.1.1-5)"
    )
    step(
        "Send multicast traffic from FRR3 to all the receivers "
        "(226.1.1.1-5, 232.1.1.1-5)"
    )

    input_src = {"i2": "i2-f1-eth0", "i5": "i5-c2-eth0"}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verifying mroutes before FRR restart, fetching uptime")

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop and Start the FRR services on FRR3 node")
    stop_router(tgen, "f1")
    start_router(tgen, "f1")

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "After stop and start of FRR service verify pim nbr is up "
        "IGMP groups received , and (*,G) (S,G) entries populated again"
        " Verify using 'show ip pim neighbor' , 'show ip igmp groups'"
        " 'show ip mroute'"
    )

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dut = "f1"
    interface = "f1-i8-eth2"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic and stop and start the FRR services on" " FRR3 node")
    shutdown_bringup_interface(tgen, "i2", "i2-f1-eth0", False)

    stop_router(tgen, "f1")
    start_router(tgen, "f1")

    step(
        "After stop and start of FRR services , all the none of (S,G)"
        " mroute should present on FRR3 node verify using "
        "'show ip mroute'"
    )

    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict = [
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "none"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    write_test_footer(tc_name)


def test_verify_SPT_switchover_when_RPT_and_SPT_path_is_different_p0(request):
    """
    TC_10: Verify SPT switchover working when RPT and SPT path is
    different
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) and " "(232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
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

    step(
        "Enable IGMP on FRR1 interface and send IGMP join "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )

    result = app_helper.run_join("i1", _IGMP_JOIN_RANGE, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to '226.1.1.1-5'" ", '232.1.1.1-5' receiver")

    step("registerRx and registerStopTx value before traffic sent")
    state_dict = {"c2": {"c2-f1-eth1": ["registerRx", "registerStopTx"]}}
    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \nError: {}".format(
        tc_name, result
    )

    result = app_helper.run_traffic("i2", _IGMP_JOIN_RANGE, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify in FRR3 sending initial packet to RP using"
        " 'show ip mroute' and mroute OIL is towards RP."
    )

    result = verify_mroutes(
        tgen,
        "f1",
        "10.0.5.2",
        _IGMP_JOIN_RANGE,
        "f1-i2-eth1",
        ["f1-c2-eth0", "f1-r2-eth3"],
    )
    assert result is True, "Testcase {} : " "Failed Error: {}".format(tc_name, result)

    result = verify_mroutes(
        tgen, "f1", "10.0.5.2", _IGMP_JOIN_RANGE, "f1-i2-eth1", "f1-r2-eth3"
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        " After spt switchover traffic is flowing between"
        " (LHR(FRR1)-FHR(FRR3)) and (S,G) OIL is updated toward FRR1"
        " 'show ip mroute' and 'show ip pim upstream'"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic to all the receivers")

    app_helper.stop_host("i2")

    step(
        "Null register packet being send periodically from FRR3 to RP, "
        "verify using show ip mroute on RP, have (S, G) entries null OIL"
        " 'show ip mroute' and verify show ip pim interface traffic"
        "(In RP Register msg should be received and Register stop should"
        " be transmitted)"
    )
    input_dict = [
        {"dut": "c2", "src_address": source, "iif": "c2-f1-eth1", "oil": "none"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("registerRx and registerStopTx value after traffic sent")
    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase {} : Failed \n state_before is not dictionary \nError: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_after_shut_noshut_of_upstream_interface_p1(request):
    """
    TC_15: Verify (S,G) and (*,G) mroute after shut / no shut of upstream
    interfaces
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c1")
    step("Configure static RP for (232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        },
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Enable IGMP on FRR1 interface and send IGMP join "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )
    step(
        "Configure IGMP interface on FRR3 and send IGMP join"
        " for group (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i1": "i1-l1-eth0", "i8": "i8-f1-eth0"}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Connect one source to c2 and send multicast traffic all"
        " the receivers (226.1.1.1-5, 232.1.1.1-5)"
    )
    step(
        "Send multicast traffic from FRR3 to all the receivers "
        "(226.1.1.1-5, 232.1.1.1-5)"
    )

    input_src = {"i2": "i2-f1-eth0", "i5": "i5-c2-eth0"}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "FRR3 (S,G) has one OIL for local receiver one toward c2"
        " verify 'show ip mroute' and 'show ip pim upstream'"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], IGMP_JOIN_RANGE_2
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut interface connected from FHR (FRR3)" " to c2")
    dut = "f1"
    intf = "f1-c2-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    step("Shut and No shut interface connected from LHR (FRR1)" " to c1")
    dut = "l1"
    intf = "l1-c1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut and No shut FRR1 and FRR3 interface")
    shutdown_bringup_interface(tgen, "l1", "l1-r2-eth4", False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    shutdown_bringup_interface(tgen, "f1", "f1-r2-eth3", False)
    shutdown_bringup_interface(tgen, dut, intf, True)

    step(
        "After shut/no shut of interface , verify traffic resume to all"
        "the receivers (S,G) OIL update for all the receivers"
    )

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut FRR1, FRR3 interface , clear mroute in FRR1"
        " and No shut FRR1, FRR3 interface "
    )
    dut = "l1"
    intf = "l1-r2-eth4"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "f1"
    intf = "f1-r2-eth3"
    shutdown_bringup_interface(tgen, dut, intf, False)

    dut = "l1"
    intf = "l1-r2-eth4"
    shutdown_bringup_interface(tgen, dut, intf, True)

    dut = "f1"
    intf = "f1-r2-eth3"
    shutdown_bringup_interface(tgen, dut, intf, True)

    clear_mroute(tgen, "l1")
    clear_mroute(tgen, "l1")

    step(
        "After no shut, verify traffic resume to all the receivers"
        " (S,G) OIL update for all the receivers"
    )

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Shut and no shut upstream interface from FRR1 to FRR2 and "
        "cisco immediate after mroute/upstream got cleared"
    )

    dut = "l1"
    intf_l1_r2 = "l1-r2-eth4"
    shutdown_bringup_interface(tgen, dut, intf_l1_r2, False)

    intf_l1_c1 = "l1-c1-eth0"
    shutdown_bringup_interface(tgen, dut, intf_l1_c1, False)

    result = verify_upstream_iif(
        tgen, "l1", "Unknown", source, IGMP_JOIN_RANGE_2, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream IIF should be unknown \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    step("No shut the Source interface just after the upstream is expired" " from FRR1")
    shutdown_bringup_interface(tgen, dut, intf_l1_r2, True)
    shutdown_bringup_interface(tgen, dut, intf_l1_c1, True)

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Stop the traffic to all the receivers")
    app_helper.stop_all_hosts()

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    write_test_footer(tc_name)


def test_verify_mroute_when_receiver_is_outside_frr_p0(request):
    """
    TC_7: Verify mroute detail when receiver is present
    outside of FRR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP on c1 for group range " "(226.1.1.1-5) and (232.1.1.1-5)")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
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

    step(
        "Enable IGMP on FRR1 interface and send IGMP join"
        " (226.1.1.1-5) and (232.1.1.1-5)"
    )
    result = app_helper.run_join("i1", _IGMP_JOIN_RANGE, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "Send multicast traffic from FRR3 to all the receivers "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )
    result = app_helper.run_traffic("i2", _IGMP_JOIN_RANGE, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure one more receiver in c2 enable IGMP and send"
        " join (226.1.1.1-5) and (232.1.1.1-5)"
    )
    input_dict = {
        "c2": {
            "igmp": {
                "interfaces": {
                    "c2-i5-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i5", _IGMP_JOIN_RANGE, "c2")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("FRR1 has 10 (*.G) and 10 (S,G) verify using 'show ip mroute count'")
    step(
        "All the receiver are receiving traffic on FRR1 and (S,G) OIL is toward"
        "receivers, verify using 'show ip mroute' 'show ip pim upstream'"
    )
    step(
        "All the receiver are receiving traffic on c2 and (S,G) OIL is "
        "toward receivers, verify using 'show ip mroute' 'show ip pim upstream'"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "c2", "src_address": "*", "iif": "c2-c1-eth0", "oil": "c2-i5-eth2"},
        {"dut": "c2", "src_address": source, "iif": "c2-f1-eth1", "oil": "c2-i5-eth2"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "FRR3 has (S,G) OIL created toward c1/c2 receiver and FRR1 receiver"
        "'show ip pim state'"
    )
    input_dict = [
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-c2-eth0"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
    ]
    for data in input_dict:
        result = verify_pim_state(
            tgen,
            data["dut"],
            data["iif"],
            data["oil"],
            _IGMP_JOIN_RANGE,
            data["src_address"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_mroute_when_FRR_is_FHR_and_LHR_p0(request):
    """
    TC_8: Verify mroute when FRR is acting as FHR and LHR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for group range (226.1.1.1-5) and " "(232.1.1.1-5) on c1")
    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
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

    step(
        "Enable IGMP on FRR1 interface and send IGMP join (226.1.1.1-5)"
        " and (232.1.1.1-5)"
    )
    step(
        "Configure receiver on FRR3 with igmp and pim enabled and "
        "send IGMP join (226.1.1.1-5) and (232.1.1.1-5)"
    )
    step(
        "Send multicast traffic from FRR3 to all the receivers "
        "(226.1.1.1-5) and (232.1.1.1-5)"
    )

    step("Send IGMP join (226.1.1.1-5, 232.1.1.1-5) to LHR(l1)")
    result = app_helper.run_join("i1", _IGMP_JOIN_RANGE, "l1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send multicast traffic from FRR3 to '226.1.1.1-5'" ", '232.1.1.1-5' receiver")
    result = app_helper.run_traffic("i2", _IGMP_JOIN_RANGE, "f1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure receiver in f1 enable IGMP and send"
        " join (226.1.1.1-5) and (232.1.1.1-5)"
    )

    step("Configure one IGMP interface on f1 node and send IGMP" " join (225.1.1.1)")
    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    result = app_helper.run_join("i8", _IGMP_JOIN_RANGE, "f1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)
    step(
        "l1 and f1 has 10 IGMP groups (226.1.1.1-5, 232.1.1.1-5),"
        " verify using 'show ip igmp groups'"
    )
    dut = "l1"
    interface = "l1-i1-eth1"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dut = "f1"
    interface = "f1-i8-eth2"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "l1 , f1 has 10 (*,G) and 10 (S,G) for groups "
        "(226.1.1.1-5, 232.1.1.1-5), verify using "
        " 'show ip mroute'"
    )

    source = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {"dut": "f1", "src_address": source, "iif": "f1-i2-eth1", "oil": "f1-r2-eth3"},
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Join timer is running in FHR and LHR , verify using" " 'show ip pim state'")

    for data in input_dict:
        result = verify_pim_state(
            tgen,
            data["dut"],
            data["iif"],
            data["oil"],
            _IGMP_JOIN_RANGE,
            data["src_address"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Stop the multicast traffic
    step("Stop the traffic to all the receivers")
    app_helper.stop_all_hosts()

    step(
        "After traffic stopped , verify (*,G) entries are not flushed"
        " out from FRR1 node verify using 'show ip mroute' "
    )

    input_dict = [
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert (
            result is True
        ), "Testcase {} : Failed Error mroutes were flushed.".format(tc_name)

    step(
        "After traffic stopped , verify (S,G) entries are flushed out"
        " from FRR1 node verify using 'show ip mroute' "
    )

    input_dict = [
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"},
        {"dut": "f1", "src_address": source, "iif": "i2-f1-eth0", "oil": "f1-r2-eth3"},
    ]

    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    write_test_footer(tc_name)


def test_verify_mroute_when_5_different_receiver_joining_same_sources_p0(request):
    """
    TC_20: Verify mroute detail when 5 different receiver joining
    same source
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c1")
    step("Configure static RP for (232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        },
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure 2 IGMP interface on FRR1 and send IGMP join"
        "for group (226.1.1.1-5, 232.1.1.1-5) from both the interface"
    )
    step(
        "Configure 2 IGMP interface on FRR3 and send IGMP join for"
        " group (226.1.1.1-5, 232.1.1.1-5) from both the interface"
    )
    step(
        "Configure 1 IGMP interface on c2 and send IGMP join for"
        "group (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    },
                    "f1-i2-eth1": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    },
                }
            }
        },
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i6-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        },
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {
        "i1": "i1-l1-eth0",
        "i6": "i6-l1-eth0",
        "i8": "i8-f1-eth0",
        "i2": "i2-f1-eth0",
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure one source in FRR2 , one in c1")
    step(
        "Send multicast traffic from both the sources to all the"
        "receivers (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_src = {"i3": "i3-r2-eth0"}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step(
        "After all the IGMP groups received with correct port using"
        " 'show ip igmp groups' in FRR1, FRR3, c2"
    )
    dut = "l1"
    interface = "l1-i6-eth2"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    dut = "f1"
    interface = "f1-i8-eth2"
    result = verify_igmp_groups(tgen, dut, interface, _IGMP_JOIN_RANGE)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "(*,G) entries got created with upstream interface RP connected"
        " port using 'show ip pim upstream' in FRR1, FRR3, c2"
    )
    step(
        "(S,G) entries created for all the receiver after starting the"
        " source , traffic is reaching to all the receiver , verify OIL"
        " of (S,G) is receiver port using 'show ip mroute' in FRR1, "
        "FRR3 c2"
    )

    source = topo["routers"]["i3"]["links"]["r2"]["ipv4"].split("/")[0]
    input_dict_all = [
        {
            "dut": "l1",
            "src_address": source,
            "iif": ["l1-r2-eth4", "l1-c1-eth0"],
            "oil": ["l1-i1-eth1", "l1-i6-eth2"],
        },
        {"dut": "f1", "src_address": source, "iif": "f1-r2-eth3", "oil": "f1-i8-eth2"},
    ]
    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the receiver interface one by one on FRR1 node")
    shutdown_bringup_interface(tgen, "l1", "l1-i1-eth1", False)
    shutdown_bringup_interface(tgen, "l1", "l1-i6-eth2", False)

    step(
        "After shut the receiver port verify traffic is stopped immediately"
        " and (S,G) got timeout immediately in FRR1, FRR3, c2"
    )
    input_dict = [
        {"dut": "l1", "src_address": source, "iif": "l1-r2-eth4", "oil": "l1-i1-eth1"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_2,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
            "Found: {}".format(tc_name, data["dut"], result)
        )

    step(
        "No traffic impact observed on other receivers verify using"
        " 'show ip mroute' "
    )
    input_dict = [
        {"dut": "f1", "src_address": source, "iif": "f1-r2-eth3", "oil": "f1-i8-eth2"}
    ]
    for data in input_dict:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("No shut the receiver interface one by one on FRR1 node")
    shutdown_bringup_interface(tgen, "l1", "l1-i1-eth1", True)
    shutdown_bringup_interface(tgen, "l1", "l1-i6-eth2", True)

    step(
        "After no shut of receivers all the mroute entries got populated"
        ", no duplicate entries present in mroute"
    )

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_oil_iif_for_mroute_after_shut_noshut_source_interface_p1(request):
    """
    TC_22: Verify OIL and IIF detail updated in (S,G) mroute after shut
    and no shut of the source interface
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("Configure static RP for (226.1.1.1-5) in c1")
    step("Configure static RP for (232.1.1.1-5) in c2")

    _GROUP_RANGE = GROUP_RANGE_2 + GROUP_RANGE_3
    _IGMP_JOIN_RANGE = IGMP_JOIN_RANGE_2 + IGMP_JOIN_RANGE_3

    input_dict = {
        "c1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c1"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_2,
                    }
                ]
            }
        },
        "c2": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": topo["routers"]["c2"]["links"]["lo"]["ipv4"].split(
                            "/"
                        )[0],
                        "group_addr_range": GROUP_RANGE_3,
                    }
                ]
            }
        },
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Configure IGMP interface on FRR1 and FRR3 and send IGMP join"
        " for group (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_dict = {
        "f1": {
            "igmp": {
                "interfaces": {
                    "f1-i8-eth2": {
                        "igmp": {"version": "2", "query": {"query-interval": 15}}
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join = {"i1": "i1-l1-eth0", "i8": "i8-f1-eth0"}

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, _IGMP_JOIN_RANGE, join_intf=recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure 1 source in FRR1 , 1 in FRR3")
    step(
        "Send multicast traffic from both the sources to all the "
        "receivers (226.1.1.1-5, 232.1.1.1-5)"
    )

    input_src = {"i6": "i6-l1-eth0", "i2": "i2-f1-eth0"}

    for src, src_intf in input_src.items():
        result = app_helper.run_traffic(src, _IGMP_JOIN_RANGE, bind_intf=src_intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "*,G) is created and (S,G) created on FRR1 and FRR3 for both"
        " the source verify using 'show ip mroute' and "
        " 'show ip pim upstream' to check the upstream interface"
        " details"
    )

    source_i6 = topo["routers"]["i6"]["links"]["l1"]["ipv4"].split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["f1"]["ipv4"].split("/")[0]
    input_dict_all = [
        {"dut": "l1", "src_address": "*", "iif": "l1-c1-eth0", "oil": "l1-i1-eth1"},
        {
            "dut": "l1",
            "src_address": source_i2,
            "iif": "l1-r2-eth4",
            "oil": "l1-i1-eth1",
        },
        {
            "dut": "l1",
            "src_address": source_i6,
            "iif": "l1-i6-eth2",
            "oil": "l1-i1-eth1",
        },
        {"dut": "f1", "src_address": "*", "iif": "f1-c2-eth0", "oil": "f1-i8-eth2"},
        {
            "dut": "f1",
            "src_address": source_i2,
            "iif": "f1-i2-eth1",
            "oil": "f1-i8-eth2",
        },
        {
            "dut": "f1",
            "src_address": source_i6,
            "iif": "f1-r2-eth3",
            "oil": "f1-i8-eth2",
        },
    ]
    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            _IGMP_JOIN_RANGE,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], _IGMP_JOIN_RANGE
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Shut the source interface one by one on FRR1")
    shutdown_bringup_interface(tgen, "f1", "f1-i2-eth1", False)

    step(
        "After shut of ource interface from FRR3 verify all the (S,G) "
        "entries flushed out from FRR3 node 'show ip pim upstream' "
        " 'show ip mroute' "
    )

    result = verify_mroutes(
        tgen,
        "f1",
        source_i2,
        _IGMP_JOIN_RANGE,
        "f1-i2-eth1",
        "f1-i8-eth2",
        expected=False,
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be present in mroute table \n "
        "Found: {}".format(tc_name, data["dut"], result)
    )

    result = verify_upstream_iif(
        tgen, "f1", "Unknown", "10.0.5.2", _IGMP_JOIN_RANGE, joinState="NotJoined"
    )
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
