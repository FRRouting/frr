#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#

"""
Following test is run in this test suite:

1. Verify IGMP prune is sent immediately once IGMPv3 join is killed
    from receiver
"""

import os
import sys
import time
import pytest
from time import sleep

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
    check_router_status,
    reset_config_on_routers,
    socat_send_ssm_join,
    kill_socat,
)

from lib.pim import (
    create_igmp_config,
    McastTesterHelper,
    verify_pim_neighbors,
    verify_mroutes,
    verify_mroutes_immediately,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

# Reading the data from JSON File for topology creation
topo = None

# Global variables
IGMP_GROUP = "232.1.1.1/32"
GROUP_RANGE_1 = [
    "232.1.1.1/32",
    "232.1.1.2/32",
    "232.1.1.3/32",
    "232.1.1.4/32",
    "232.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["232.1.1.1", "232.1.1.2", "232.1.1.3", "232.1.1.4", "232.1.1.5"]

r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_ssm_topo2.json".format(testdir)
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
    build_config_from_json(tgen, tgen.json_topo)

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".format(result)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    app_helper.cleanup()
    kill_socat(tgen, action="remove_ssm_join")

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


def test_verify_igmp_prune_is_sent_immediately_p0(request):
    """
    Verify IGMP prune is sent immediately once IGMPv3 join is killed from
    receiver

    Topology:
    h1 (source) — r1 (FHR) — r2 — r3 — r4 (LHR) — h4 (receiver)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Configure IGMP on R4 to h1(receiver) connected port")
    intf_r4_h2 = topo["routers"]["r4"]["links"]["h2"]["interface"]

    input_dict = {
        "r4": {"igmp": {"interfaces": {intf_r4_h2: {"igmp": {"version": "3"}}}}}
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        'Configure "ip pim ssm enable" on all the nodes enable as part of initial setup'
    )

    step("Send IGMPv3 join from R4 for group range 232.1.1.1-5")

    source_h1 = topo["routers"]["h1"]["links"]["r1"]["ipv4"].split("/")[0]

    intf_ip = topo["routers"]["h2"]["links"]["r4"]["ipv4"].split("/")[0]
    result = socat_send_ssm_join(
        tgen, "h2", "UDP-RECV", IGMP_JOIN_RANGE_1, intf_ip, source_h1
    )
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic from h1(source) to r1")
    result = app_helper.run_traffic("h1", IGMP_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Wait at least 30 sec so pimd updates stats from kernel and starts KA timer")
    sleep(30)

    input_dict_sg_r2_r4 = [
        {
            "dut": "r2",
            "src_address": source_h1,
            "iif": topo["routers"]["r2"]["links"]["r1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r3"]["interface"],
        },
        {
            "dut": "r3",
            "src_address": source_h1,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r4"]["interface"],
        },
        {
            "dut": "r4",
            "src_address": source_h1,
            "iif": topo["routers"]["r4"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r4"]["links"]["h2"]["interface"],
        },
    ]

    input_dict_sg_r1 = [
        {
            "dut": "r1",
            "src_address": source_h1,
            "iif": topo["routers"]["r1"]["links"]["h1"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"],
        },
    ]

    for input_dict in [input_dict_sg_r2_r4, input_dict_sg_r1]:
        for data in input_dict:
            result = verify_mroutes(
                tgen,
                data["dut"],
                data["src_address"],
                IGMP_JOIN_RANGE_1,
                data["iif"],
                data["oil"],
            )
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Kill IGMP join from receiver(h2)")
    kill_socat(tgen, "h2", action="remove_ssm_join")

    step("Verify igmp prune is sent immediately from R4-R1")
    input_dict_sg_r1 = [
        {
            "dut": "r1",
            "src_address": source_h1,
            "iif": topo["routers"]["r1"]["links"]["h1"]["interface"],
            "oil": "none",
        },
    ]

    for data in input_dict_sg_r2_r4:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False
        )
        assert (
            result is not True
        ), ("Testcase {} : Failed " "Mroutes are still present \n "
        " IGMP prune is not sent immediately \n Error: {}".format(
            tc_name, result
        ))

    for data in input_dict_sg_r1:
        result = verify_mroutes_immediately(
            tgen,
            data["dut"],
            data["src_address"],
            IGMP_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))