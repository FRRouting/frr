# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
#

"""
Following tests are covered to test_multicast_pim_mld_local_tier_1:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:

1. Verify static MLD group populated when static "ip mld join <grp>" in configured
2. Verify mroute and upstream populated with correct OIL/IIF with static imld join
3. Verify local MLD join not allowed for non multicast group
4. Verify static MLD group removed from DUT while removing "ip mld join" CLI
5. Verify static MLD groups after removing and adding MLD config
"""

import sys
import time

import pytest
from lib.common_config import (
    reset_config_on_routers,
    start_topology,
    step,
    write_test_footer,
    write_test_header,
)
from lib.pim import (
    McastTesterHelper,
    create_mld_config,
    create_pim_config,
    verify_local_mld_groups,
    verify_mld_groups,
    verify_mroutes,
    verify_pim_neighbors,
    verify_pim_rp_info,
    verify_upstream_iif,
)
from lib.bgp import (
    verify_bgp_convergence,
)

from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r2_r4_links = []
r3_r1_links = []
r3_r4_links = []
r4_r2_links = []
r4_r3_links = []

pytestmark = [pytest.mark.pim6d, pytest.mark.staticd]

TOPOLOGY = """
               +-------------------+
               |                   |
        i1--- R1-------R2----------R4---i2
               |                   |
               +-------R3----------+


    Description:
    i1, i2, i3. i4, i5, i6, i7, i8 - FRR running iperf to send MLD
                                     join and traffic
    R1 - DUT (LHR)
    R2 - RP
    R3 - Transit
    R4 - (FHR)

"""
# Global variables

GROUP_RANGE = "ffaa::/16"
RP_RANGE = "ff00::/8"
GROUP_RANGE_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
MLD_JOIN_RANGE_1 = ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]
MLD_JOIN_RANGE_2 = [
    "ff02::1:ff00:0",
    "ff02::d",
    "fe80::250:56ff:feb7:d8d5",
    "2001::4",
    "2002::5",
]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "multicast_mld_local_join.json"
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

    # Verify BGP convergence
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

    # Verify PIM neighbors
    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".format(result)

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


def test_mld_local_joins_p0(request):
    """
    Verify static MLD group populated when static
    "ipv6 mld join <grp>" in configured
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the MLD on R11 interfac of R1 and configure local mld groups")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}},
                    intf_r1_i2: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}},
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

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

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify mld groups using show ipv6  mld groups")
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_mroute_with_mld_local_joins_p0(request):
    """
    Verify mroute and upstream populated with correct OIL/IIF with
    static mld join
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the MLD on R11 interfac of R1 and configure local mld groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}},
                    intf_r1_i2: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}},
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

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

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify mld groups using show ipv6  mld groups")
    interfaces = [intf_r1_i1, intf_r1_i2]
    for interface in interfaces:
        result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("verify RP-info populated in DUT")
    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send traffic from R4 to all the groups ( ffaa::1 to ffaa::5)")
    result = app_helper.run_traffic("i4", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "'show ipv6  mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )
    source_i6 = topo["routers"]["i4"]["links"]["r4"]["ipv6"].split("/")[0]

    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]

    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": intf_r1_r2,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": "*",
            "iif": intf_r1_r2,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
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

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Verify mroutes not created with local interface ip ")
    input_dict_local_sg = [
        {
            "dut": "r1",
            "src_address": intf_r1_i1,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        },
        {
            "dut": "r1",
            "src_address": intf_r1_i2,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"],
        },
    ]

    for data in input_dict_local_sg:
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
            "Testcase {} : Failed Error: {}"
            "sg created with local interface ip".format(tc_name, result)
        )

        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed Error: {}"
            "upstream created with local interface ip".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_remove_add_mld_local_joins_p1(request):
    """
    Verify static MLD group removed from DUT while
    removing "ip mld join" CLI
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the MLD on R11 interfac of R1 and configure local mld groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]

    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}}
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

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

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify mld groups using show ipv6  mld groups")

    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify RP-info populated in DUT")
    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    oif = topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, oif, rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send traffic from R4 to all the groups ( ffaa::1 to ffaa::5)")
    result = app_helper.run_traffic("i4", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "'show ipv6  mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )
    source_i6 = topo["routers"]["i4"]["links"]["r4"]["ipv6"].split("/")[0]

    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": intf_r1_r2,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
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

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Remove MLD join from DUT")
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "join": MLD_JOIN_RANGE_1,
                            "delete_attr": True,
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static mld join removed using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(
        tgen, dut, interface, MLD_JOIN_RANGE_1, expected=False
    )
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "MLD join still present".format(
        tc_name, result
    )

    step("verify mld groups removed using show ipv6  mld groups")
    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "MLD groups still present".format(
        tc_name, result
    )

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
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
            assert (
                result is not True
            ), "Testcase {} : Failed Error: {}" "mroutes still present".format(
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
            assert (
                result is not True
            ), "Testcase {} : Failed Error: {}" "mroutes still present".format(
                tc_name, result
            )

    step("Add MLD join on DUT again")
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "join": MLD_JOIN_RANGE_1,
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify mld groups using show ipv6  mld groups")

    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
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

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_remove_add_mld_config_with_local_joins_p1(request):
    """
    Verify static MLD groups after removing
    and adding MLD config
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reset_config_on_routers(tgen)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    app_helper.stop_all_hosts()

    step("Enable the PIM on all the interfaces of R1, R2, R3, R4")
    step("configure BGP on R1, R2, R3, R4 and enable redistribute static/connected")
    step("Enable the MLD on R11 interfac of R1 and configure local mld groups")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}}
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

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

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify mld groups using show ipv6  mld groups")
    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Send traffic from R4 to all the groups ( ffaa::1 to ffaa::5)")
    result = app_helper.run_traffic("i4", MLD_JOIN_RANGE_1, "r4")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        "'show ipv6  mroute' showing correct RPF and OIF interface for (*,G)"
        " and (S,G) entries on all the nodes"
    )
    source_i6 = topo["routers"]["i4"]["links"]["r4"]["ipv6"].split("/")[0]

    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    input_dict_starg = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": intf_r1_r2,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    input_dict_sg = [
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": topo["routers"]["r1"]["links"]["r4"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
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

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    step("Remove mld and mld version 2 from DUT interface")
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {intf_r1_i1: {"mld": {"version": "1", "delete": True}}}
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(
        tgen, dut, interface, MLD_JOIN_RANGE_1, expected=False
    )
    assert result is not True, "Testcase {} :Failed \n Error: {}".format(
        tc_name, result
    )

    step("verify mld groups using show ipv6  mld groups")
    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} :Failed \n Error: {}" "MLD grsp still present".format(
        tc_name, result
    )

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
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
            assert (
                result is not True
            ), "Testcase {} : Failed Error: {}" "mroutes still present".format(
                tc_name, result
            )

    step("Add mld and mld version 2 from DUT interface")
    input_dict = {
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {"mld": {"version": "1", "join": MLD_JOIN_RANGE_1}}
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify static mld join using show ipv6  mld join")
    dut = "r1"
    interface = intf_r1_i1
    result = verify_local_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("verify mld groups using show ipv6 mld groups")
    interface = intf_r1_i1
    result = verify_mld_groups(tgen, dut, interface, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify mroutes and iff upstream for local mld groups")
    for input_dict in [input_dict_starg, input_dict_sg]:
        for data in input_dict:
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

            result = verify_upstream_iif(
                tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
