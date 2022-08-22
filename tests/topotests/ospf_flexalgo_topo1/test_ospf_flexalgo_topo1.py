#!/usr/bin/python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
test_ospf_flexalgo_topo1.py:

                         +---------+
                eth-rt1-1|         |eth-rt1-2
              +----------+ 1.1.1.1 +-----------+
              |          |   RT1   |           |
              |          |         |           |
              |          +---------+           |
   10.0.1.0/24|                                |10.0.2.0/24
              |                                |
     eth-rt2-1|                                |eth-rt3-1
         +---------+                     +---------+
         |         |                     |         |
         |   RT2   |     10.0.3.0/24     |   RT3   |
         | 2.2.2.2 +---------------------+ 3.3.3.3 |
         |         |eth-rt2-3   eth-rt3-3|         |
         +---------+                     +---------+
     eth-rt2-2|                                |eth-rt3-2
              |                                |
   10.0.4.0/24|                                |10.0.5.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT4   |           |
              +----------+ 4.4.4.4 +-----------+
                eth-rt4-1|         |eth-rt4-2
                         +---------+
"""

import os
import sys
import pytest
import json
from functools import partial
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.common_config import (
    start_topology,
    write_test_footer,
    step,
    start_router,
    apply_raw_config,
)

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt1-1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt1-2")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt2-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt4-1")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt3-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt4-2")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt2-3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt3-3")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            # TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd_flxalg.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


def router_compare_json_output(rname, command, reference, check_for_mismatch = False):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    if check_for_mismatch :
        diff = None
        for count in range(1,10):
            _, diff = topotest.run_and_expect(test_func, None, count=5, wait=1)
            if diff is not None:
                # if there's some diff we have achieved the desired condition
                break
            # Else retry few more times
        #if still there's no diff, then the desired condition failed
        if diff is None:
            assertmsg = '"{}" JSON output matches the not-to-be expected result'.format(rname)
            logger.info('Not-to-be-Expected result:\n========\n{}\n=========='.format(expected))
            logger.info('Actual result:\n========\n{}\n========'.format(tgen.gears[rname].vtysh_cmd(command)))
            assert False, assertmsg
    else :
        _, diff = topotest.run_and_expect(test_func, None, count=60, wait=1)
        if diff is not None:
            assertmsg = '"{}" JSON output mismatches the expected result, Diff:\n{}\n'.format(rname, diff)
            logger.info('Expected result:\n========\n{}\n=========='.format(expected))
            logger.info('Actual result:\n========\n{}\n========'.format(tgen.gears[rname].vtysh_cmd(command)))
            assert False, assertmsg

def router_compare_text_output(rname, command, reference, check_for_mismatch = False):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = open(filename).read()

    # Run test function until we get an result. Wait at most 80 seconds.
    test_func = partial(
        topotest.router_output_cmp, tgen.gears[rname], command, expected
    )
    if check_for_mismatch :
        result = None
        for count in range(1,10):
            result, diff = topotest.run_and_expect(test_func, None, count=5, wait=1)
            if result is not None:
                # if there's some diff we have achieved the desired condition
                break
            # Else retry few more times
        #if still there's no diff, then the desired condition failed
        if result is None:
            assertmsg = '"{}" Text output matches the not-to-be expected result:\n'.format(rname)
            logger.info('Not-to-be-Expected result:\n========\n{}\n=========='.format(expected))
            logger.info('Actual result:\n========\n{}\n========'.format(tgen.gears[rname].vtysh_cmd(command)))
            assert False, assertmsg
    else :
        result, diff = topotest.run_and_expect(test_func, "", count=3, wait=3.5)
        if not result:
            assertmsg = '"{}" Text output mismatches the expected result. Diff:\n {}\n'.format(rname, diff)
            logger.info('Expected result:\n========\n{}\n=========='.format(expected))
            logger.info('Actual result:\n========\n{}\n========'.format(tgen.gears[rname].vtysh_cmd(command)))
            assert False, assertmsg

"""
Step 1

Test initial network convergence
"""
def test_rib_step1(request):
    tgen = get_topogen()
    tc_name = request.node.name

    step("Verify initial RIB")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ip route ospf json",
            "step1/show_ip_route.ref"
        )

    write_test_footer(tc_name)


def test_opaque_lsa_step1(request):
    tgen = get_topogen()

    tc_name = request.node.name
    step("Verify OSPF Opaque LSA advertisemenst for Flex-Algorithms")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)


"""
 Step 2

 Action(s):
 -Add another flexible-algo on rt4 with default configurations

 Expected changes:
 -rt4 should advertise an additional FAD TLV in the RI-LSA with
  following attributes and values
   -- metric-type: igp
   -- calculation-type: spf
   -- priority: 0
 - rt4 should not advertise any additional FAPM or FAAM subTLVs
   for algorithm 129.

 Action(s):
 -Try deleting the flexible-algo on rt4 that was added in step 2

 Expected changes:
 -rt4 should remove Flex-Algo with id 129.
 -rt2 MUST NOT advertise any FAD TLV in the RI-LSA or any
   FAPM or FAAM subTLVs for algo 129.
"""
def test_flex_algo_default_add_step2(request):
    tgen = get_topogen()

    tc_name = request.node.name
    step("Add another flex-algo with defaults on rt4")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    raw_config = {
        "rt4": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 129"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step2/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step2/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step2/show_ip_ospf_database_opaque_mismatch.ref",
            check_for_mismatch=True
        )

    step("Try deleting flex-algo with algorithm Id 129 on rt4")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    raw_config = {
        "rt4": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 129"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete Flex-Algo 129!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 3

 Action(s):
 -Try adding flexible-algo on rt2 with algo-id outside permitted
  range

 Expected changes:
 -rt2 should not allow configuration.
 -rt2 MUST NOT advertise any FAD TLV in the RI-LSA or any
   FAPM or FAAM subTLVs.
"""
def test_flex_algo_id_config_range_step3(request):
    tgen = get_topogen()

    tc_name = request.node.name
    step("Try adding flex-algo with invalid algorithm Id on rt2")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    raw_config = {
        "rt2": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 127"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is False, "Testcase {} : Invalid configuration applied successfully!".format(tc_name)

    raw_config = {
        "rt2": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 256"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is False, "Testcase {} : Invalid configuration applied successfully!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 4

 Action(s):
 -Modify the priority of flexible-algo 128 on rt1

 Expected changes:
 -rt1 should update the Flex-Algo with new priority.
 -rt1 MUST advertise the FAD TLV for 128 with new value of priority.
"""
def test_flex_algo_modify_priority_step4(request):
    tgen = get_topogen()

    tc_name = request.node.name
    step("Try modifying priority of flex-algo with algorithm Id 128 on rt1 to 20")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 priority 20"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to modify priority of Flex-Algo 128 on rt1!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step4/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step4/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 5

 Action(s):
 -Delete the priority of flexible-algo 128 on rt1

 Expected changes:
 -rt1 should update the Flex-Algo with default priority of 0
 -rt1 MUST advertise the FAD TLV for 128 with new value of priority.

 Action(s):
 -Restore the original priority of flexible-algo 128 on rt1

 Expected changes:
 -rt1 should update the Flex-Algo with with priority 10.
 -rt1 MUST advertise the FAD TLV for 128 with new value of priority.
"""
def test_flex_algo_default_priority_metrictype_calctype_step5(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Try deleting priority of flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 priority"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete priority of Flex-Algo 128 on rt1!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step5/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step5/show_ip_ospf_database_opaque.ref"
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Try deleting metric-type of flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 metric-type"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete metric-type of Flex-Algo 128 on rt1!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step5/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step5/show_ip_ospf_database_opaque.ref"

        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Try deleting calcultation-type of flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 calculation-type"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete calculation-type of Flex-Algo 128 on rt1!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step5/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step5/show_ip_ospf_database_opaque.ref"

        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Try restoring priority of flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 priority 10"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to set priority of Flex-Algo 128 on rt1!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 6

 Add and delete exclude-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_add_delete_excadmingrp_step6(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add an existing exclude-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should not update the Flex-Algo with any new exclude-admin-group.
     -rt1 MUST NOT advertise the FAD TLV for 128 with any new exclude-admin-group
      included in the Exclude-Admin-Groups SubTLV.
    """

    step("Try adding same again exclude admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-admin-group red"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add same exclude-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step6/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add a new exclude-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with new exclude-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with new exclude-admin-group
      included in the Exclude-Admin-Groups SubTLV.
    """
    step("Try adding new exclude admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-admin-group yellow"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add another exclude-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step6/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step6/show_ip_ospf_database_opaque.ref"
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete the newly added exclude-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove the new exclude-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the new exclude-admin-group
      included in the Exclude-Admin-Groups SubTLV.
    """
    step("Try deleting the new exclude admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 exclude-admin-group yellow"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete exclude-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step6/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step6/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    write_test_footer(tc_name)

"""
 Step 7

 Add and delete exclude-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_delete_all_excadmingrp_step7(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete all exclude-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove all exclude-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the Exclude-Admin-Groups SubTLV.
    """
    step("Try deleting all exclude admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 exclude-admin-group"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete all exclude-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step7/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step7/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add back the original exclude-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with corresponding exclude-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with original exclude-admin-group
      included in the Exclude-Admin-Groups SubTLV.
    """
    step("Try adding original exclude admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-admin-group red"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add exclude-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 8

 Add and delete include-any-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_add_delete_incany_admingrp_step8(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add an existing include-any-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should not update the Flex-Algo with any new include-any-admin-group.
     -rt1 MUST NOT advertise the FAD TLV for 128 with any new include-any-admin-group
      included in the include-any-Admin-Groups SubTLV.
    """

    step("Try adding same again include-any admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-any-admin-group green"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add same include-any-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step8/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add a new include-any-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with new include-any-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with new include-any-admin-group
      included in the include-any-Admin-Groups SubTLV.
    """
    step("Try adding new include-any admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-any-admin-group yellow"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add another include-any-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step8/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step8/show_ip_ospf_database_opaque.ref"
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete the newly added include-any-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove the new include-any-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the new include-any-admin-group
      included in the include-any-Admin-Groups SubTLV.
    """
    step("Try deleting the new include-any admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 include-any-admin-group yellow"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete include-any-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step8/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step8/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    write_test_footer(tc_name)

"""
 Step 9

 Add and delete include-all-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_delete_any_incany_admingrp_step9(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete all include-any-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove all include-any-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the include-any-Admin-Groups SubTLV.
    """
    step("Try deleting all include-any admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 include-any-admin-group"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete all include-any-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step9/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step9/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add back the original include-any-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with corresponding include-any-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with original include-any-admin-group
      included in the include-any-Admin-Groups SubTLV.
    """
    step("Try adding original include-any admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-any-admin-group green",
                "flexible-algorithm 128 include-any-admin-group blue",
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add include-any-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 10

 Add and delete include-all-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_add_delete_incall_admingrp_step10(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add an existing include-all-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should not update the Flex-Algo with any new include-all-admin-group.
     -rt1 MUST NOT advertise the FAD TLV for 128 with any new include-all-admin-group
      included in the include-all-Admin-Groups SubTLV.
    """

    step("Try adding same again include-all admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-all-admin-group green"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add same include-all-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step10/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add a new include-all-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with new include-all-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with new include-all-admin-group
      included in the include-all-Admin-Groups SubTLV.
    """
    step("Try adding new include-all admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-all-admin-group blue"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add another include-all-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step10/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step10/show_ip_ospf_database_opaque.ref"
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete the newly added include-all-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove the new include-all-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the new include-all-admin-group
      included in the include-all-Admin-Groups SubTLV.
    """
    step("Try deleting the new include-all admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 include-all-admin-group blue"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete include-all-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step10/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step10/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    write_test_footer(tc_name)

"""
 Step 11

 Add and delete include-all-admin-group to flexible-algo 128 on rt1
"""
def test_flex_algo_delete_all_incall_admingrp_step11(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete all include-all-admin-group from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove all include-all-admin-group from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the include-all-Admin-Groups SubTLV.
    """
    step("Try deleting all include-all admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 include-all-admin-group"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete all include-all-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step11/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step11/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add back the original include-all-admin-group to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with corresponding include-all-admin-group.
     -rt1 MUST advertise the FAD TLV for 128 with original include-all-admin-group
      included in the include-all-Admin-Groups SubTLV.
    """
    step("Try adding original include-all admin-group for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 include-all-admin-group green"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add include-all-admin-group of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 12

 Add and delete exclude-srlg to flexible-algo 128 on rt1
"""
def test_flex_algo_add_delete_exc_srlg_step12(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add an existing exclude-srlg to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should not update the Flex-Algo with any new exclude-srlg.
     -rt1 MUST NOT advertise the FAD TLV for 128 with any new exclude-srlg
      included in the Exclude-SRLGs SubTLV.
    """

    step("Try adding same again exclude srlg for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-srlg 10"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add same exclude-srlg of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step12/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add a new exclude-srlg to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with new exclude-srlg.
     -rt1 MUST advertise the FAD TLV for 128 with new exclude-srlg
      included in the Exclude-SRLGs SubTLV.
    """
    step("Try adding new exclude srlg for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-srlg 40"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add another exclude-srlg of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step12/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step12/show_ip_ospf_database_opaque.ref"
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete the newly added exclude-srlg from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove the new exclude-srlg from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the new exclude-srlg
      included in the Exclude-SRLGs SubTLV.
    """
    step("Try deleting the new exclude srlg for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 exclude-srlg 40"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete exclude-srlg of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step12/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step12/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    write_test_footer(tc_name)

"""
 Step 13

 Add and delete exclude-srlg to flexible-algo 128 on rt1
"""
def test_flex_algo_delete_all_exc_srlg_step13(request):
    tgen = get_topogen()

    tc_name = request.node.name

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Delete all exclude-srlg from flexible-algo 128 on rt1

     Expected changes:
     -rt1 should remove all exclude-srlg from the Flex-Algo.
     -rt1 MUST advertise the FAD TLV for 128 without the Exclude-SRLGs SubTLV.
    """
    step("Try deleting all exclude srlg for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no flexible-algorithm 128 exclude-srlg"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete all exclude-srlg of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step13/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref", check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step13/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    """
     Action(s):
     -Add back the original exclude-srlg to flexible-algo 128 on rt1

     Expected changes:
     -rt1 should update the Flex-Algo with corresponding exclude-srlg.
     -rt1 MUST advertise the FAD TLV for 128 with original exclude-srlg
      included in the Exclude-SRLGs SubTLV.
    """
    step("Try adding original exclude srlg for flex-algo with algorithm Id 128 on rt1")
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 exclude-srlg 10"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to add exclude-srlg of Flex-Algo 128 on rt1 again!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

"""
 Step 14
"""
def test_flex_algo_delete_prefix_advt_metric_step14(request):
    tgen = get_topogen()

    tc_name = request.node.name

    """
     Action(s):
     -Delete the advertise-prefix-metric of flexible-algo 128 on rt4

     Expected changes:
     -rt4 should remove Ext-Prefix LSA and Ext-IASBR LSA for the Flex Algo 128.
    """

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Try deleting advertise-prefix-metric of flex-algo with algorithm Id 128 on rt4")
    # But set the LSA Maxage timer to a much shorter interval for verification
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "ospf maxage-delay 1",
            ]
        },
        "rt2": {
            "raw_config": [
                "router ospf",
                "ospf maxage-delay 1",
            ]
        },
        "rt3": {
            "raw_config": [
                "router ospf",
                "ospf maxage-delay 1",
            ]
        },
        "rt4": {
            "raw_config": [
                "router ospf",
                "ospf maxage-delay 1",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)

    raw_config = {
        "rt4": {
            "raw_config": [
                "router ospf",
                "ospf maxage-delay 1",
                "no flexible-algorithm 128 advertise-prefix-metric"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to delete advertise-prefix-metric of Flex-Algo 128 on rt4!".format(tc_name)

    # LSA deletion will take upto few seconds. So let's wait for it.
    topotest.sleep(2)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step14/show_ip_ospf_flexalgo.ref"
        )
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref",
            check_for_mismatch=True
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step14/show_ip_ospf_database_opaque.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref",
            check_for_mismatch=True
        )

    # Revert back the LSA Maxage timer to default
    raw_config = {
        "rt1": {
            "raw_config": [
                "router ospf",
                "no ospf maxage-delay",
            ]
        },
        "rt2": {
            "raw_config": [
                "router ospf",
                "no ospf maxage-delay",
            ]
        },
        "rt3": {
            "raw_config": [
                "router ospf",
                "no ospf maxage-delay",
            ]
        },
        "rt4": {
            "raw_config": [
                "router ospf",
                "no ospf maxage-delay",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)

    """
     Action(s):
     -Modify the advertise-prefix-metric of flexible-algo 128 on rt4

     Expected changes:
     -rt1 should update the Flex-Algo with new advertise-metric.
     -rt1 MUST advertise the FAPM and FAAM (in a new Ext-IASBR LSA)
      subTLVs for 128 with new value.
    """
    step("Try restoring advertise-prefix-metric of flex-algo with algorithm Id 128 on rt4")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    raw_config = {
        "rt4": {
            "raw_config": [
                "router ospf",
                "flexible-algorithm 128 advertise-prefix-metric 10"
            ]
        }
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed to set advertise-prefix-metric of Flex-Algo 128 on rt4!".format(tc_name)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_text_output(
            rname, "show ip ospf router-info flexible-algorithms",
            "step1/show_ip_ospf_flexalgo.ref"
        )
        router_compare_json_output(
            rname, "show ip ospf database opaque-area json",
            "step1/show_ip_ospf_database_opaque.ref"
        )

    write_test_footer(tc_name)

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
