#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_pim_autorp.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step, write_test_header

from lib.pim import (
    create_pim_config,
    create_igmp_config,
    verify_igmp_groups,
    verify_mroutes,
    get_pim_interface_traffic,
    verify_upstream_iif,
    verify_pim_join,
    clear_mroute,
    clear_pim_interface_traffic,
    verify_igmp_config,
    McastTesterHelper,
)

"""
test_pim_dense.py: Test general PIM dense mode functionality
"""

TOPOLOGY = """
   Basic PIM Dense Mode functionality
                                            +--+--+
                              Mcast Source  | H1  |
                                            +--+--+
                                               | .2 h1-eth0
                                               |
                                               |   10.100.0.0/24
                                               |
                                               | .1 r1-eth1
                                            +--+--+
                                            | R1  |
                                            +--+--+
                                               | .1 r1-eth0
                                               |
                                               |   10.0.0.0/24
                                               |
                                               | .2 r2-eth0
  10.101.0.0/24  +--+--+     10.0.2.0/24    +--+--+
            -----| R4  |--------------------| R2  |
              .1 +--+--+ .2              .1 +--+--+
          r4-eth1        r4-eth0     r2-eth2   | .1 r2-eth1
                                               |
                                               |   10.0.1.0.24
                                               |
                                               | .2 r3-eth0
  10.102.0.0/24  +--+--+    10.0.3.0/24     +--+--+    10.0.4.0/24     +--+--+  10.103.0.0/24
            -----| R5  |--------------------| R3  |--------------------| R6  |-----
              .1 +--+--+ .2              .1 +--+--+ .1              .2 +--+--+ .1
          r5-eth1        r5-eth0     r3-eth1    r3-eth2         r6-eth0       r6-eth1
"""

DENSE_GROUP="239.1.1.1"
SSM_GROUP="232.1.1.1"

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]


# Initially set up the data with no joined routes, but all the nodes should show the route
# as long as traffic is flowing

pim_dense_input_dict = {
        "r1": {"src_address": "10.100.0.2", "iif": "r1-eth1", "oil": "none", "joinState": "NotJoined"},
        "r2": {"src_address": "10.100.0.2", "iif": "r2-eth0", "oil": "none", "joinState": "NotJoined"},
        "r3": {"src_address": "10.100.0.2", "iif": "r3-eth0", "oil": "none", "joinState": "NotJoined"},
        "r4": {"src_address": "10.100.0.2", "iif": "r4-eth0", "oil": "none", "joinState": "NotJoined"},
        "r5": {"src_address": "10.100.0.2", "iif": "r5-eth0", "oil": "none", "joinState": "NotJoined"},
        "r6": {"src_address": "10.100.0.2", "iif": "r6-eth0", "oil": "none", "joinState": "NotJoined"},
    }

def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_host("h1", "10.100.0.2/24", "via 10.100.0.1")

    # Create topology links
    tgen.add_link(tgen.gears["h1"], tgen.gears["r1"], "h1-eth0", "r1-eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"], "r2-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2-eth2", "r4-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r5"], "r3-eth1", "r5-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r6"], "r3-eth2", "r6-eth0")

    tgen.gears["r4"].run("ip link add r4-eth1 type dummy")
    tgen.gears["r5"].run("ip link add r5-eth1 type dummy")
    tgen.gears["r6"].run("ip link add r6-eth1 type dummy")

def setup_module(mod):
    logger.info("PIM Dense mode basic functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    logger.info("Testing PIM Dense Mode support")
    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")



def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def test_pim_dense_flood_and_prune(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify 'show ip mroute' showing routes with no OIL on all the nodes")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        for dut, data in pim_dense_input_dict.items():
            result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_graft_r4(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Join on R4 and check forwarding
        tgen.routers()["r4"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'ip igmp join {}'").format("r4-eth1", DENSE_GROUP))
        pim_dense_input_dict["r1"]["oil"] = "r1-eth0"
        pim_dense_input_dict["r1"]["joinState"] = "Joined"
        pim_dense_input_dict["r2"]["oil"] = "r2-eth2"
        pim_dense_input_dict["r2"]["joinState"] = "Joined"
        pim_dense_input_dict["r4"]["oil"] = "r4-eth1"
        pim_dense_input_dict["r4"]["joinState"] = "Joined"

        step("Verify 'show ip mroute' showing routes just to R4")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        for dut, data in pim_dense_input_dict.items():
            result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_graft_r5(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Join on R5 and check forwarding
        tgen.routers()["r5"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'ip igmp join {}'").format("r5-eth1", DENSE_GROUP))

        pim_dense_input_dict["r2"]["oil"] = ["r2-eth2","r2-eth1"]
        pim_dense_input_dict["r2"]["joinState"] = "Joined"
        pim_dense_input_dict["r3"]["oil"] = "r3-eth1"
        pim_dense_input_dict["r3"]["joinState"] = "Joined"
        pim_dense_input_dict["r5"]["oil"] = "r5-eth1"
        pim_dense_input_dict["r5"]["joinState"] = "Joined"

        step("Verify 'show ip mroute' showing routes to R4 and R5")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        for dut, data in pim_dense_input_dict.items():
            result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)



def test_pim_dense_graft_r6(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Join on R6 and check forwarding
        tgen.routers()["r6"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'ip igmp join {}'").format("r6-eth1", DENSE_GROUP))

        pim_dense_input_dict["r3"]["oil"] = ["r3-eth1","r3-eth2"]
        pim_dense_input_dict["r3"]["joinState"] = "Joined"
        pim_dense_input_dict["r6"]["oil"] = "r6-eth1"
        pim_dense_input_dict["r6"]["joinState"] = "Joined"

        step("Verify 'show ip mroute' showing routes to R4 and R5 and R6")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        for dut, data in pim_dense_input_dict.items():
            result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_prune_r4(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Leave on R4 and check forwarding
        tgen.routers()["r4"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'no ip igmp join {}'").format("r4-eth1", DENSE_GROUP))

        pim_dense_input_dict["r4"]["oil"] = "none"
        pim_dense_input_dict["r4"]["joinState"] = "NotJoined"
        pim_dense_input_dict["r2"]["oil"] = "r2-eth1"
        pim_dense_input_dict["r2"]["joinState"] = "Joined"

        step("Verify 'show ip mroute' showing routes to R5 and R6")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        # for dut, data in pim_dense_input_dict.items():
        #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
        #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)



def test_pim_dense_prune_r5(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Leave on R5 and check forwarding
        tgen.routers()["r5"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'no ip igmp join {}'").format("r5-eth1", DENSE_GROUP))

        pim_dense_input_dict["r5"]["oil"] = "none"
        pim_dense_input_dict["r5"]["joinState"] = "NotJoined"
        pim_dense_input_dict["r3"]["oil"] = "r3-eth2"
        pim_dense_input_dict["r3"]["joinState"] = "Joined"

        step("Verify 'show ip mroute' showing routes to R6")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        # for dut, data in pim_dense_input_dict.items():
        #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
        #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_prune_r6(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    with McastTesterHelper(tgen) as app_helper:
        step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Leave on R6 and check forwarding
        tgen.routers()["r6"].cmd(("vtysh -c 'conf t' -c 'int {}' -c 'no ip igmp join {}'").format("r6-eth1", DENSE_GROUP))

        pim_dense_input_dict["r6"]["oil"] = "none"
        pim_dense_input_dict["r6"]["joinState"] = "NotJoined"
        pim_dense_input_dict["r3"]["oil"] = "none"
        pim_dense_input_dict["r3"]["joinState"] = "NotJoined"
        pim_dense_input_dict["r2"]["oil"] = "none"
        pim_dense_input_dict["r2"]["joinState"] = "NotJoined"
        pim_dense_input_dict["r1"]["oil"] = "none"
        pim_dense_input_dict["r1"]["joinState"] = "NotJoined"

        step("Verify 'show ip mroute' showing routes with no OIL")
        for dut, data in pim_dense_input_dict.items():
            result = verify_mroutes(tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # TODO
        # Moving to not joined state on R1 takes like 30 seconds, then after that, R2 takes
        # another 2 minutes until it moves to not joined state...that is entirely too long.
        # After the leave it should be pretty immediate to go to not joined
        # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
        # for dut, data in pim_dense_input_dict.items():
        #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
        #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))