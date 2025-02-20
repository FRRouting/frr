#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_gr_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf6_gr_topo1.py:

             +---------+
             |   RT1   |
             | 1.1.1.1 |
             +---------+
                  |eth-rt2
                  |
                  |eth-rt1
             +---------+
             |   RT2   |
             | 2.2.2.2 |
             +---------+
                  |eth-rt3
                  |
                  |eth-rt2
             +---------+
             |   RT3   |
             | 3.3.3.3 |
             +---------+
          eth-rt4|  |eth-rt6
                 |  |
       +---------+  +--------+
       |                     |
       |eth-rt3              |eth-rt3
  +---------+           +---------+
  |   RT4   |           |   RT6   |
  | 4.4.4.4 |           | 6.6.6.6 |
  +---------+           +---------+
       |eth-rt5              |eth-rt7
       |                     |
       |eth-rt4              |eth-rt6
  +---------+           +---------+
  |   RT5   |           |   RT7   |
  | 5.5.5.5 |           | 7.7.7.7 |
  +---------+           +---------+
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
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
)

pytestmark = [pytest.mark.ospf6d]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


def build_topo(tgen):
    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="stub1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt3")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt3")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt6")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt7"], nodeif="stub1")


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
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference, tries):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=tries, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def expect_grace_lsa(restarting, helper):
    """
    Check if the given helper neighbor has already received a Grace-LSA from
    the router performing a graceful restart.
    """
    tgen = get_topogen()

    logger.info(
        "'{}': checking if a Grace-LSA was received from '{}'".format(
            helper, restarting
        )
    )
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[helper],
        "show ipv6 ospf6 database json",
        {
            "interfaceScopedLinkStateDb": [
                {
                    "lsa": [
                        {
                            "type": "GR",
                            "advRouter": restarting,
                        }
                    ]
                }
            ]
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"{}" didn\'t receive a Grace-LSA from "{}"'.format(helper, restarting)

    assert result is None, assertmsg


def check_routers(initial_convergence=False, exiting=None, restarting=None):
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7"]:
        # Check the RIB first, which should be preserved across restarts in
        # all routers of the routing domain.
        # If we are not on initial convergence *but* we are checking
        # after a restart.  Looking in the zebra rib for installed
        # is a recipe for test failure.  Why?  because if we are restarting
        # then ospf is in the process of establishing neighbors and passing
        # new routes to zebra.  Zebra will not mark the route as installed
        # when it receives a replacement from ospf until it has finished
        # processing it.  Let's give it a few seconds to allow this to happen
        # under load.
        if initial_convergence == True:
            tries = 240
        else:
            if restarting != None:
                tries = 40
            else:
                tries = 10
        router_compare_json_output(
            rname, "show ipv6 route ospf json", "show_ipv6_route.json", tries
        )

        # Check that all adjacencies are up and running (except when there's
        # an OSPF instance that is shutting down).
        if exiting == None:
            tries = 240
            router_compare_json_output(
                rname,
                "show ipv6 ospf neighbor json",
                "show_ipv6_ospf_neighbor.json",
                tries,
            )

        # Check the OSPF RIB and LSDB.
        # In the restarting router, wait up to one minute for the LSDB to converge.
        if exiting != rname:
            if initial_convergence == True or restarting == rname:
                tries = 240
            else:
                tries = 10
            router_compare_json_output(
                rname,
                "show ipv6 ospf database json",
                "show_ipv6_ospf_database.json",
                tries,
            )
            router_compare_json_output(
                rname, "show ipv6 ospf route json", "show_ipv6_ospf_route.json", tries
            )


def ensure_gr_is_in_zebra(rname):
    retry = True
    retry_times = 10
    tgen = get_topogen()

    while retry and retry_times > 0:
        out = tgen.net[rname].cmd(
            'vtysh -c "show zebra client" | grep "Client: ospf6$" -A 40 | grep "Capabilities "'
        )

        if "Graceful Restart" not in out:
            sleep(2)
            retry_times -= 1
        else:
            retry = False

    assertmsg = "%s does not appear to have Graceful Restart setup" % rname
    assert not retry and retry_times > 0, assertmsg


#
# Test initial network convergence
#
def test_initial_convergence():
    logger.info("Test: verify initial network convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_routers(initial_convergence=True)


#
# Test rt1 performing a graceful restart
#
def test_gr_rt1():
    logger.info("Test: verify rt1 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt1"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="1.1.1.1", helper="rt2")
    ensure_gr_is_in_zebra("rt1")
    kill_router_daemons(tgen, "rt1", ["ospf6d"], save_config=False)
    check_routers(exiting="rt1")
    start_router_daemons(tgen, "rt1", ["ospf6d"])
    check_routers(restarting="rt1")


#
# Test rt2 performing a graceful restart
#
def test_gr_rt2():
    logger.info("Test: verify rt2 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt2"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="2.2.2.2", helper="rt1")
    expect_grace_lsa(restarting="2.2.2.2", helper="rt3")
    ensure_gr_is_in_zebra("rt2")
    kill_router_daemons(tgen, "rt2", ["ospf6d"], save_config=False)
    check_routers(exiting="rt2")

    start_router_daemons(tgen, "rt2", ["ospf6d"])
    check_routers(restarting="rt2")


#
# Test rt3 performing a graceful restart
#
def test_gr_rt3():
    logger.info("Test: verify rt3 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt3"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="3.3.3.3", helper="rt2")
    expect_grace_lsa(restarting="3.3.3.3", helper="rt4")
    expect_grace_lsa(restarting="3.3.3.3", helper="rt6")
    ensure_gr_is_in_zebra("rt3")
    kill_router_daemons(tgen, "rt3", ["ospf6d"], save_config=False)
    check_routers(exiting="rt3")

    start_router_daemons(tgen, "rt3", ["ospf6d"])
    check_routers(restarting="rt3")


#
# Test rt4 performing a graceful restart
#
def test_gr_rt4():
    logger.info("Test: verify rt4 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt4"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="4.4.4.4", helper="rt3")
    expect_grace_lsa(restarting="4.4.4.4", helper="rt5")
    ensure_gr_is_in_zebra("rt4")
    kill_router_daemons(tgen, "rt4", ["ospf6d"], save_config=False)
    check_routers(exiting="rt4")

    start_router_daemons(tgen, "rt4", ["ospf6d"])
    check_routers(restarting="rt4")


#
# Test rt5 performing a graceful restart
#
def test_gr_rt5():
    logger.info("Test: verify rt5 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt5"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="5.5.5.5", helper="rt4")
    ensure_gr_is_in_zebra("rt5")
    kill_router_daemons(tgen, "rt5", ["ospf6d"], save_config=False)
    check_routers(exiting="rt5")

    start_router_daemons(tgen, "rt5", ["ospf6d"])
    check_routers(restarting="rt5")


#
# Test rt6 performing a graceful restart
#
def test_gr_rt6():
    logger.info("Test: verify rt6 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt6"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="6.6.6.6", helper="rt3")
    expect_grace_lsa(restarting="6.6.6.6", helper="rt7")
    ensure_gr_is_in_zebra("rt6")
    kill_router_daemons(tgen, "rt6", ["ospf6d"], save_config=False)
    check_routers(exiting="rt6")

    start_router_daemons(tgen, "rt6", ["ospf6d"])
    check_routers(restarting="rt6")


#
# Test rt7 performing a graceful restart
#
def test_gr_rt7():
    logger.info("Test: verify rt7 performing a graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["rt7"].cmd('vtysh -c "graceful-restart prepare ipv6 ospf"')
    expect_grace_lsa(restarting="6.6.6.6", helper="rt6")
    ensure_gr_is_in_zebra("rt7")
    kill_router_daemons(tgen, "rt7", ["ospf6d"], save_config=False)
    check_routers(exiting="rt7")

    start_router_daemons(tgen, "rt7", ["ospf6d"])
    check_routers(restarting="rt7")


#
# Test rt1 performing an unplanned graceful restart
#
def test_unplanned_gr_rt1():
    logger.info("Test: verify rt1 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt1", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt1", ["ospf6d"])

    expect_grace_lsa(restarting="1.1.1.1", helper="rt2")
    ensure_gr_is_in_zebra("rt1")
    check_routers(restarting="rt1")


#
# Test rt2 performing an unplanned graceful restart
#
def test_unplanned_gr_rt2():
    logger.info("Test: verify rt2 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt2", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt2", ["ospf6d"])

    expect_grace_lsa(restarting="2.2.2.2", helper="rt1")
    expect_grace_lsa(restarting="2.2.2.2", helper="rt3")
    ensure_gr_is_in_zebra("rt2")
    check_routers(restarting="rt2")


#
# Test rt3 performing an unplanned graceful restart
#
def test_unplanned_gr_rt3():
    logger.info("Test: verify rt3 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt3", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt3", ["ospf6d"])

    expect_grace_lsa(restarting="3.3.3.3", helper="rt2")
    expect_grace_lsa(restarting="3.3.3.3", helper="rt4")
    expect_grace_lsa(restarting="3.3.3.3", helper="rt6")
    ensure_gr_is_in_zebra("rt3")
    check_routers(restarting="rt3")


#
# Test rt4 performing an unplanned graceful restart
#
def test_unplanned_gr_rt4():
    logger.info("Test: verify rt4 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt4", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt4", ["ospf6d"])

    expect_grace_lsa(restarting="4.4.4.4", helper="rt3")
    expect_grace_lsa(restarting="4.4.4.4", helper="rt5")
    ensure_gr_is_in_zebra("rt4")
    check_routers(restarting="rt4")


#
# Test rt5 performing an unplanned graceful restart
#
def test_unplanned_gr_rt5():
    logger.info("Test: verify rt5 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt5", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt5", ["ospf6d"])

    expect_grace_lsa(restarting="5.5.5.5", helper="rt4")
    ensure_gr_is_in_zebra("rt5")
    check_routers(restarting="rt5")


#
# Test rt6 performing an unplanned graceful restart
#
def test_unplanned_gr_rt6():
    logger.info("Test: verify rt6 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt6", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt6", ["ospf6d"])

    expect_grace_lsa(restarting="6.6.6.6", helper="rt3")
    expect_grace_lsa(restarting="6.6.6.6", helper="rt7")
    ensure_gr_is_in_zebra("rt6")
    check_routers(restarting="rt6")


#
# Test rt7 performing an unplanned graceful restart
#
def test_unplanned_gr_rt7():
    logger.info("Test: verify rt7 performing an unplanned graceful restart")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "rt7", ["ospf6d"], save_config=False)
    start_router_daemons(tgen, "rt7", ["ospf6d"])

    expect_grace_lsa(restarting="6.6.6.6", helper="rt6")
    ensure_gr_is_in_zebra("rt7")
    check_routers(restarting="rt7")


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
