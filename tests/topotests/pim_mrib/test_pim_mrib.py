#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_mrib.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest
from functools import partial

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import (
    verify_pim_rp_info,
)
from lib.common_config import step, write_test_header

"""
test_pim_mrib.py: Test PIM MRIB overrides and RPF modes
"""

TOPOLOGY = """
   Test PIM MRIB overrides and RPF modes

            +---+---+                      +---+---+
            |       |     10.0.0.0/24      |       |
            +  R1   +----------------------+  R2   |
            |       | .1                .2 |       |
            +---+---+ r1-eth0      r2-eth0 +---+---+
             .1 | r1-eth1              r2-eth1 | .2
                |                              |
   10.0.1.0/24  |                              |  10.0.2.0/24
                |                              |
             .3 | r3-eth0              r4-eth0 | .4
            +---+---+ r3-eth1      r4-eth1 +---+---+
            |       | .3                .4 |       |
            +  R3   +----------------------+  R4   |
            |       |      10.0.3.0/24     |       |
            +---+---+                      +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]


def build_topo(tgen):
    '''Build function'''

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    # Create topology links
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2-eth1", "r4-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r4"], "r3-eth1", "r4-eth1")


def setup_module(mod):
    logger.info("PIM MRIB/RPF functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

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
    '''Teardown the pytest environment'''
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_mrib_init(request):
    '''Test boot in MRIB-than-URIB with the default MRIB'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify rp-info using default URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_override(request):
    '''Test MRIB override nexthop'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Install a MRIB route that has a shorter prefix length and lower cost.
    # In MRIB-than-URIB mode, it should use this route
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         ip mroute 10.0.0.0/16 10.0.3.3 25
        '''
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_prefix_mode(request):
    '''Test longer prefix lookup mode'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to longer prefix match, should switch back to the URIB route
    # even with the lower cost, the longer prefix match will win because of the mode
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         router pim
          rpf-lookup-mode longer-prefix
        '''
    )

    step("Verify rp-info using URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_dist_mode(request):
    '''Test lower distance lookup mode'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to lower distance match, should switch back to the MRIB route
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         router pim
          rpf-lookup-mode lower-distance
        '''
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_urib_mode(request):
    '''Test URIB only lookup mode'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to urib only match, should switch back to the URIB route
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         router pim
          rpf-lookup-mode urib-only
        '''
    )

    step("Verify rp-info using URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_mrib_mode(request):
    '''Test MRIB only lookup mode'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to mrib only match, should switch back to the MRIB route
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         router pim
          rpf-lookup-mode mrib-only
        '''
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_pim_mrib_mrib_mode_no_route(request):
    '''Test MRIB only with no route'''
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Remove the MRIB route, in mrib-only mode, it should switch to no path for the RP
    tgen.routers()["r4"].vtysh_cmd(
        '''
        conf term
         no ip mroute 10.0.0.0/16 10.0.3.3 25
        '''
    )

    step("Verify rp-info with Unknown next hop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "Unknown",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

def test_memory_leak():
    '''Run the memory leak test and report results.'''
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
