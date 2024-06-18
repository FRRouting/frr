#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_sr_te_topo1.py
#
# Copyright (c) 2021 by
# Volta Networks
#

"""
test_ospf_sr_te_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+          + 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|                      eth-rt5-1|  |eth-rt5-2
             |                               |  |
  10.0.2.0/24|                    10.0.4.0/24|  |10.0.5.0/24
             |                               |  |
    eth-rt2-1|                      eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.11.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         | 9.9.9.2 |
                         |         |
                         +---------+

"""

import os
import sys
import pytest
import json
from time import sleep
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.pathd]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "dst"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    # switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    # switch = tgen.add_switch("s3")
    # switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    # switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built in:" + frrdir)

    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def setup_testcase(msg):
    logger.info(msg)
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    return tgen


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


def compare_json_test(router, command, reference, exact):
    output = router.vtysh_cmd(command, isjson=True)
    result = topotest.json_cmp(output, reference)

    # Note: topotest.json_cmp() just checks on inclusion of keys.
    # For exact matching also compare the other way around.
    if not result and exact:
        return topotest.json_cmp(reference, output)
    else:
        return result


def cmp_json_output(rname, command, reference, exact=False):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(compare_json_test, tgen.gears[rname], command, expected, exact)
    _, diff = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def cmp_json_output_exact(rname, command, reference):
    return cmp_json_output(rname, command, reference, True)


def add_candidate_path(rname, endpoint, pref, name, segment_list="default"):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color 1 endpoint """
        + endpoint
        + """" \
              -c "candidate-path preference """
        + str(pref)
        + """ name """
        + name
        + """ explicit segment-list """
        + segment_list
        + '''"'''
    )


def delete_candidate_path(rname, endpoint, pref):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color 1 endpoint """
        + endpoint
        + """" \
              -c "no candidate-path preference """
        + str(pref)
        + '''"'''
    )


def add_segment(rname, name, index, label):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "segment-list """
        + name
        + """" \
              -c "index """
        + str(index)
        + """ mpls label """
        + str(label)
        + '''"'''
    )


def delete_segment(rname, name, index):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "segment-list """
        + name
        + """" \
              -c "no index """
        + str(index)
        + '''"'''
    )


def add_segment_adj(rname, name, index, src, dst):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "segment-list """
        + name
        + """" \
              -c "index """
        + str(index)
        + """ nai adjacency """
        + str(src)
        + """ """
        + str(dst)
        + '''"'''
    )


def create_sr_policy(rname, endpoint, bsid):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color 1 endpoint """
        + endpoint
        + """" \
              -c "name default" \
              -c "binding-sid """
        + str(bsid)
        + '''"'''
    )


def delete_sr_policy(rname, endpoint):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "no policy color 1 endpoint """
        + endpoint
        + '''"'''
    )


def create_prefix_sid(rname, prefix, sid):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "router ospf " \
              -c "segment-routing prefix """
        + prefix
        + " index "
        + str(sid)
        + '''"'''
    )


def delete_prefix_sid(rname, prefix):
    get_topogen().net[rname].cmd(
        ''' \
        vtysh -c "conf t" \
              -c "router ospf " \
              -c "no segment-routing prefix "'''
        + prefix
    )


def check_bsid(rt, bsid, fn_name, positive):
    """
    Search for a bsid in rt1 and rt6
    Positive means that check is true is bsid is found
    Positive="False" means that check is true is bsid is NOT found
    """

    logger.info('Checking "%s" bsid "%s" for router "%s" ', positive, bsid, rt)

    count = 0
    candidate_key = bsid
    candidate_output = ""
    # First wait for convergence
    tgen = get_topogen()
    while count < 30:
        matched = False
        matched_key = False
        sleep(1)
        count += 1
        router = tgen.gears[rt]
        candidate_output = router.vtysh_cmd("show mpls table json")
        candidate_output_json = json.loads(candidate_output)
        for item in candidate_output_json.items():
            # logger.info('item "%s"', item)
            if item[0] == candidate_key:
                matched_key = True
                if positive:
                    break
        if positive:
            if matched_key:
                matched = True
            assertmsg = "{} don't has entry {} but is was expected".format(
                router.name, candidate_key
            )
        else:
            if not matched_key:
                matched = True
            assertmsg = "{} has entry {} but is wans't expected".format(
                router.name, candidate_key
            )
        if matched:
            logger.info('Success "%s" in "%s"', router.name, fn_name)
            return
    assert matched, assertmsg


#
# Step 1
#
# Checking the MPLS table using a single SR Policy and a single Candidate Path
# Segment list are base in adjacency that query TED
#
def test_srte_init_step1():
    setup_testcase("Test (step 1): wait OSPF convergence / label distribution")

    check_bsid("rt1", "1111", test_srte_init_step1.__name__, False)
    check_bsid("rt6", "6666", test_srte_init_step1.__name__, False)


def test_srte_add_candidate_check_mpls_table_step1():
    setup_testcase("Test (step 1): check MPLS table regarding the added Candidate Path")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_candidate_path(rname, endpoint, 100)


def test_srte_reinstall_sr_policy_check_mpls_table_step1():
    setup_testcase(
        "Test (step 1): check MPLS table after the SR Policy was removed and reinstalled"
    )

    for rname, endpoint, bsid in [("rt1", "6.6.6.6", 1111), ("rt6", "1.1.1.1", 6666)]:
        add_candidate_path(rname, endpoint, 100, "default")
        delete_sr_policy(rname, endpoint)
        check_bsid(rname, bsid, test_srte_init_step1.__name__, False)
        create_sr_policy(rname, endpoint, bsid)
        add_candidate_path(rname, endpoint, 100, "default")
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_candidate_path(rname, endpoint, 100)


#
# Step 2
#
# Checking pathd operational data using a single SR Policy and a single Candidate Path
# Segment list are base in adjacency that query TED
#
def test_srte_bare_policy_step2():
    setup_testcase("Test (step 2): bare SR Policy should not be operational")

    for rname in ["rt1", "rt6"]:
        cmp_json_output_exact(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step2/show_operational_data.ref",
        )


def test_srte_add_candidate_check_operational_data_step2():
    setup_testcase(
        "Test (step 2): add single Candidate Path, SR Policy should be operational"
    )

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        cmp_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step2/show_operational_data_with_candidate.ref",
        )


def test_srte_config_remove_candidate_check_operational_data_step2():
    setup_testcase(
        "Test (step 2): remove single Candidate Path, SR Policy should not be operational anymore"
    )

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        delete_candidate_path(rname, endpoint, 100)
        cmp_json_output_exact(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step2/show_operational_data.ref",
        )


#
# Step 3
#
# Testing the Candidate Path selection
# Segment list are based in adjacencies resolved by query TED
#
def test_srte_add_two_candidates_step3():
    setup_testcase("Test (step 3): second Candidate Path has higher Priority")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        for pref, cand_name in [("100", "first"), ("200", "second")]:
            add_candidate_path(rname, endpoint, pref, cand_name)
        cmp_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step3/show_operational_data_with_two_candidates.ref",
        )

    # cleanup
    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        for pref in ["100", "200"]:
            delete_candidate_path(rname, endpoint, pref)


def test_srte_add_two_candidates_with_reverse_priority_step3():
    setup_testcase("Test (step 3): second Candidate Path has lower Priority")

    # Use reversed priorities here
    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        for pref, cand_name in [("200", "first"), ("100", "second")]:
            add_candidate_path(rname, endpoint, pref, cand_name)
        cmp_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step3/show_operational_data_with_two_candidates.ref",
        )

    # cleanup
    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        for pref in ["100", "200"]:
            delete_candidate_path(rname, endpoint, pref)


def test_srte_remove_best_candidate_step3():
    setup_testcase("Test (step 3): delete the Candidate Path with higher priority")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        for pref, cand_name in [("100", "first"), ("200", "second")]:
            add_candidate_path(rname, endpoint, pref, cand_name)

    # Delete candidate with higher priority
    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        delete_candidate_path(rname, endpoint, 200)

    # Candidate with lower priority should get active now
    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        cmp_json_output(
            rname,
            "show yang operational-data /frr-pathd:pathd pathd",
            "step3/show_operational_data_with_single_candidate.ref",
        )
        # cleanup
        delete_candidate_path(rname, endpoint, 100)


#
# Step 4
#
# Checking MPLS table with a single SR Policy and a Candidate Path with different Segment Lists and other modifications
# Segment list are base in adjacency that query TED
#
def test_srte_change_segment_list_check_mpls_table_step4():
    setup_testcase("Test (step 4): check MPLS table for changed Segment List")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        # now change the segment list name
        add_candidate_path(rname, endpoint, 100, "default", "test")
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_segment(rname, "test", 10)
        delete_segment(rname, "test", 20)
        delete_segment(rname, "test", 30)
        delete_segment(rname, "test", 40)
        if rname == "rt1":
            add_segment_adj(rname, "test", 10, "10.0.1.1", "10.0.1.2")
            add_segment_adj(rname, "test", 20, "10.0.2.2", "10.0.2.4")
            add_segment_adj(rname, "test", 30, "10.0.6.4", "10.0.6.5")
            add_segment_adj(rname, "test", 40, "10.0.8.5", "10.0.8.6")
        else:
            add_segment_adj(rname, "test", 10, "10.0.8.6", "10.0.8.5")
            add_segment_adj(rname, "test", 20, "10.0.6.5", "10.0.6.4")
            add_segment_adj(rname, "test", 30, "10.0.2.4", "10.0.2.2")
            add_segment_adj(rname, "test", 40, "10.0.1.2", "10.0.1.1")
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_candidate_path(rname, endpoint, 100)


def test_srte_change_sl_priority_error_ted_check_mpls_table_step4():
    setup_testcase("Test (step 4): check MPLS table keeps low prio sl")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        # now change the segment list name
        add_candidate_path(rname, endpoint, 200, "test", "test")
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_segment(rname, "test", 10)
        delete_segment(rname, "test", 20)
        delete_segment(rname, "test", 30)
        delete_segment(rname, "test", 40)
        # These won't resolv
        if rname == "rt1":
            add_segment_adj(rname, "test", 10, "10.0.1.99", "10.0.1.99")
            add_segment_adj(rname, "test", 20, "10.0.2.99", "10.0.2.99")
            add_segment_adj(rname, "test", 30, "10.0.6.99", "10.0.6.99")
            add_segment_adj(rname, "test", 40, "10.0.8.99", "10.0.8.99")
        else:
            add_segment_adj(rname, "test", 10, "10.0.8.99", "10.0.8.99")
            add_segment_adj(rname, "test", 20, "10.0.6.99", "10.0.6.99")
            add_segment_adj(rname, "test", 30, "10.0.2.99", "10.0.2.99")
            add_segment_adj(rname, "test", 40, "10.0.1.99", "10.0.1.99")
        # So policy sticks with default sl even higher prio
        check_bsid(
            rname,
            "1111" if rname == "rt1" else "6666",
            test_srte_init_step1.__name__,
            True,
        )
        delete_candidate_path(rname, endpoint, 100)


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
