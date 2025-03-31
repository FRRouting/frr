#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_sr_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_isis_sr_te_topo1.py:

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
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
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

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd, pytest.mark.pathd]


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
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

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
        pytest.skip("pathd daemon wasn't built")

    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
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
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def cmp_json_output_exact(rname, command, reference):
    return cmp_json_output(rname, command, reference, True)


def compare_json_test_inverted(router, command, reference, exact):
    "logically inverts result of compare_json_test"

    # None vs something else
    result = compare_json_test(router, command, reference, exact)
    if result is None:
        return "Some"
    return None


def cmp_json_output_doesnt(rname, command, reference):
    "Compare router JSON output, shouldn't include reference"

    logger.info('Comparing (anti) router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(
        compare_json_test_inverted, tgen.gears[rname], command, expected, exact=False
    )
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def dump_json(v):
    if isinstance(v, (dict, list)):
        return "\t" + "\t".join(
            json.dumps(v, indent=4, separators=(",", ": ")).splitlines(True)
        )
    else:
        return "'{}'".format(v)


def add_candidate_path(rname, endpoint, pref, name, segment_list="default", color=1):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color """
        + str(color)
        + " endpoint "
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


def delete_candidate_path(rname, endpoint, pref, color=1):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color """
        + str(color)
        + " endpoint "
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
              -c "router isis 1" \
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
              -c "router isis 1" \
              -c "no segment-routing prefix "'''
        + prefix
    )


def set_route_map_color(rname, color):
    get_topogen().net[rname].cmd(
        ''' \
        vtysh -c "conf t" \
              -c "route-map SET_SR_POLICY permit 10" \
              -c "set sr-te color  "'''
        + str(color)
    )


def router_bgp_shutdown_neighbor(rname, neighbor):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "router bgp 1" \
              -c " neighbor """
        + neighbor
        + ' shutdown"'
    )


def router_bgp_no_shutdown_neighbor(rname, neighbor):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "router bgp 1" \
              -c " no neighbor """
        + neighbor
        + ' shutdown"'
    )


def show_running_cfg(rname):
    output = (
        get_topogen()
        .net[rname]
        .cmd(
            """ \
        vtysh -c "show run" """
        )
    )
    logger.info(output)


#
# Step 1
#
# Checking the MPLS table using a single SR Policy and a single Candidate Path
#
def test_srte_init_step1():
    setup_testcase("Test (step 1): wait for IS-IS convergence / label distribution")

    for rname in ["rt1", "rt6"]:
        cmp_json_output(
            rname, "show mpls table json", "step1/show_mpls_table_without_candidate.ref"
        )


def test_srte_add_candidate_check_mpls_table_step1():
    setup_testcase("Test (step 1): check MPLS table regarding the added Candidate Path")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        cmp_json_output(
            rname, "show mpls table json", "step1/show_mpls_table_with_candidate.ref"
        )
        delete_candidate_path(rname, endpoint, 100)


def test_srte_reinstall_sr_policy_check_mpls_table_step1():
    setup_testcase(
        "Test (step 1): check MPLS table after the SR Policy was removed and reinstalled"
    )

    for rname, endpoint, bsid in [("rt1", "6.6.6.6", 1111), ("rt6", "1.1.1.1", 6666)]:
        add_candidate_path(rname, endpoint, 100, "default")
        delete_sr_policy(rname, endpoint)
        cmp_json_output(
            rname, "show mpls table json", "step1/show_mpls_table_without_candidate.ref"
        )
        create_sr_policy(rname, endpoint, bsid)
        add_candidate_path(rname, endpoint, 100, "default")
        cmp_json_output(
            rname, "show mpls table json", "step1/show_mpls_table_with_candidate.ref"
        )
        delete_candidate_path(rname, endpoint, 100)


#
# Step 2
#
# Checking pathd operational data using a single SR Policy and a single Candidate Path
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
#
def test_srte_change_segment_list_check_mpls_table_step4():
    setup_testcase("Test (step 4): check MPLS table for changed Segment List")

    for rname, endpoint in [("rt1", "6.6.6.6"), ("rt6", "1.1.1.1")]:
        add_candidate_path(rname, endpoint, 100, "default")
        # now change the segment list name
        add_candidate_path(rname, endpoint, 100, "default", "test")
        cmp_json_output(rname, "show mpls table json", "step4/show_mpls_table.ref")
        delete_candidate_path(rname, endpoint, 100)


def test_srte_segment_list_add_segment_check_mpls_table_step4():
    setup_testcase(
        "Test (step 4): check MPLS table for added (then changed and finally deleted) segment"
    )

    add_candidate_path("rt1", "6.6.6.6", 100, "default", "test")

    # first add a new segment
    add_segment("rt1", "test", 25, 16050)
    cmp_json_output(
        "rt1", "show mpls table json", "step4/show_mpls_table_add_segment.ref"
    )

    # ... then change it ...
    add_segment("rt1", "test", 25, 16030)
    cmp_json_output(
        "rt1", "show mpls table json", "step4/show_mpls_table_change_segment.ref"
    )

    # ... and finally delete it
    delete_segment("rt1", "test", 25)
    cmp_json_output("rt1", "show mpls table json", "step4/show_mpls_table.ref")
    delete_candidate_path("rt1", "6.6.6.6", 100)


def save_rt(routername, filename):
    save_filename = routername + "/" + filename
    tgen = get_topogen()
    router = tgen.gears[routername]

    config_output = router.vtysh_cmd("sh run")

    route_output_json = json.loads(router.vtysh_cmd("show ip route bgp json"))
    route_output = dump_json(route_output_json)

    f = open(save_filename, "w")
    f.write(config_output)
    f.write(route_output)
    f.close()


#
# Step 5
#
# Checking the nexthop using a single SR Policy and a Candidate Path with configured route-map
#
def test_srte_route_map_with_sr_policy_check_nextop_step5():
    setup_testcase(
        "Test (step 5): recursive nexthop learned through BGP neighbour should be aligned with SR Policy from route-map"
    )

    # (re-)build the SR Policy two times to ensure that reinstalling still works
    for _ in [1, 2]:
        cmp_json_output(
            "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_inactive_srte.ref"
        )

        delete_sr_policy("rt1", "6.6.6.6")
        cmp_json_output(
            "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_inactive_srte.ref"
        )

        create_sr_policy("rt1", "6.6.6.6", 1111)
        cmp_json_output(
            "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_inactive_srte.ref"
        )

        add_candidate_path("rt1", "6.6.6.6", 100, "default")
        cmp_json_output(
            "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
        )

        delete_candidate_path("rt1", "6.6.6.6", 100)


def test_srte_route_map_sr_policy_vs_route_order_step5():
    setup_testcase(
        "Test (step 5): Config policy first, add route after and check route validity"
    )

    #
    # BGP route and route-map are already configured.
    # route-map sets color 1 on BGP routes

    # Developer: to force pause here
    # tgen = get_topogen()
    # tgen.mininet_cli()

    #
    # Configure policy/path
    #
    add_candidate_path("rt1", "6.6.6.6", 100, "default", "default", 1)

    #
    # Route should be valid
    #
    logger.info(
        "BGP route and route-map are already configured, SR candidate path added after. Route should be valid"
    )
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    #
    # shutdown/no-shutdown on BGP neighbor to delete/re-add BGP route
    #
    router_bgp_shutdown_neighbor("rt1", "6.6.6.6")
    router_bgp_no_shutdown_neighbor("rt1", "6.6.6.6")

    #
    # Route should be valid (but isn't)
    #
    logger.info(
        "After shutdown + no-shutdown neighbor. Route should be valid, but isn't"
    )
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    #
    # delete and re-add policy/path
    #
    delete_candidate_path("rt1", "6.6.6.6", 100, 1)
    add_candidate_path("rt1", "6.6.6.6", 100, "default", "default", 1)

    #
    # Route should be valid
    #
    logger.info("After re-add candidate path. Route should be valid")
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    # Developer: to force pause here
    # tgen = get_topogen()
    # tgen.mininet_cli()

    # clean up
    delete_candidate_path("rt1", "6.6.6.6", 100, 2)


def test_srte_route_map_sr_policy_vs_routemap_order_step5():
    setup_testcase(
        "Test (step 5): Config policy first, set route-map after and check route validity"
    )

    #
    # BGP route and route-map are already configured.
    # route-map sets color 1 on BGP routes
    #

    #
    # Configure policy/path
    #
    add_candidate_path("rt1", "6.6.6.6", 100, "default", "default", 1)

    #
    # Route should be valid
    #
    logger.info("After add candidate path. Route should be valid")
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    # Developer: to force pause here
    # tgen = get_topogen()
    # tgen.mininet_cli()

    #
    # change route-map color to someting else and back again
    #
    set_route_map_color("rt1", 2)
    logger.info("route-map color was set to 2")
    # show_running_cfg("rt1")
    # 220625 nexthop no longer becomes empty. Colored routes without
    # matching SR policies now fall back to their non-colored equivalent
    # nexthops. So the route to 9.9.9.9/32 will now be valid, but with
    # different nexthop values.
    logger.info("now route table will lose policy-mapped route")
    cmp_json_output_doesnt(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )
    set_route_map_color("rt1", 1)
    logger.info("route-map color was set to 1")
    # show_running_cfg("rt1")

    #
    # Route should be valid (but isn't)
    #
    logger.info("After change route-map color. Route should be valid, but isn't")
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    #
    # delete and re-add policy/path
    #
    delete_candidate_path("rt1", "6.6.6.6", 100, 1)
    add_candidate_path("rt1", "6.6.6.6", 100, "default", "default", 1)

    #
    # Route should be valid
    #
    logger.info("After delete/re-add candidate path. Route should be valid")
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )

    # Developer: force pause
    # tgen = get_topogen()
    # tgen.mininet_cli()

    # clean up
    delete_candidate_path("rt1", "6.6.6.6", 100, 2)


def test_srte_route_map_with_sr_policy_reinstall_prefix_sid_check_nextop_step5():
    setup_testcase(
        "Test (step 5): remove and re-install prefix SID on fist path element and check SR Policy activity"
    )

    # first add a candidate path so the SR Policy is active
    add_candidate_path("rt1", "6.6.6.6", 100, "default")
    cmp_json_output(
        "rt1",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step5/show_operational_data_active.ref",
    )

    # delete prefix SID from first element of the configured path and check
    # if the SR Policy is inactive since the label can't be resolved anymore
    delete_prefix_sid("rt5", "5.5.5.5/32")
    cmp_json_output(
        "rt1",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step5/show_operational_data_inactive.ref",
    )
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_inactive_srte.ref"
    )

    # re-create the prefix SID and check if the SR Policy is active
    create_prefix_sid("rt5", "5.5.5.5/32", 50)
    cmp_json_output(
        "rt1",
        "show yang operational-data /frr-pathd:pathd pathd",
        "step5/show_operational_data_active.ref",
    )
    cmp_json_output(
        "rt1", "show ip route bgp json", "step5/show_ip_route_bgp_active_srte.ref"
    )


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
