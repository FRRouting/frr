#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_srv6_tilfa_backup.py
# Part of FRR/NetDEF Topology Tests
#
# Copyright (c) 2026 Free Mobile, Vincent Jardin
#

"""
test_isis_srv6_tilfa_backup.py:

Test IS-IS TI-LFA with SRv6 backup routes verification using 'show isis route backup'.

This test specifically verifies that:
1. Backup routes are correctly computed with SRv6 segment stacks
2. The 'show isis route backup json' command shows correct SRv6 SIDs
3. Routes within Ext-P-Space correctly show no SIDs (using direct backup nexthop)
4. Multi-hop backup paths show correct End SID + End.X SID combinations

Topology (Diamond):

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                     eth-rt2|   |eth-rt3
                            |   |
                 10.0.1.0/24|   |10.0.2.0/24
                            |   |
                     eth-rt1|   |eth-rt1
         +---------+        |   |        +---------+
         |         |--------+   +--------|         |
         |   RT2   |                     |   RT3   |
         | 2.2.2.2 |                     | 3.3.3.3 |
         |         |                     |         |
         +---------+                     +---------+
              |eth-rt4                   eth-rt4|
              |                                 |
   10.0.3.0/24|                                 |10.0.4.0/24
              |                                 |
              |eth-rt2                   eth-rt3|
              +----------+---------+------------+
                         |         |
                         |   RT4   |
                         | 4.4.4.4 |
                         |         |
                         +---------+

SRv6 Locators:
- RT1: fc00:0:1::/48
- RT2: fc00:0:2::/48
- RT3: fc00:0:3::/48
- RT4: fc00:0:4::/48

TI-LFA Protection:
- All interfaces have TI-LFA enabled
- This creates backup paths for all destinations

Expected Backup Routes (from RT1's perspective):
- fc00:0:2::/48: Primary via RT2, backup via RT3->RT2 (needs End.X SID)
- fc00:0:3::/48: Primary via RT3, backup via RT2->RT3 (needs End.X SID)
- fc00:0:4::/48: Primary via RT2->RT4, backup via RT3->RT4 (may need End SID + End.X SID)
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
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import (
    create_interface_in_kernel,
    check_kernel_seg6_support,
    enable_srv6_on_router,
)

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    """Build function"""

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4"]:
        tgen.add_router(router)

    #
    # Define connections
    #

    # RT1 - RT2 link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    # RT1 - RT3 link
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt1")

    # RT2 - RT4 link
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2")

    # RT3 - RT4 link
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt3")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )


def setup_module(mod):
    """Sets up the pytest environment"""

    # Check if kernel supports SRv6 (seg6)
    seg6_supported, seg6_enabled = check_kernel_seg6_support()
    if not seg6_supported:
        pytest.skip(
            "Kernel does not support SRv6: net.ipv6.conf.all.seg6_enabled sysctl not available. "
            "Please enable CONFIG_IPV6_SEG6_LWTUNNEL in your kernel configuration."
        )

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Enable SRv6 (seg6) on all routers if not already enabled
    if not seg6_enabled:
        logger.info("Enabling SRv6 (seg6) on all routers")
    for rname, router in tgen.routers().items():
        if not enable_srv6_on_router(router):
            tgen.set_error("Failed to enable SRv6 on router {}".format(rname))

    router_list = tgen.routers()

    # For all registered routers, load the unified frr configuration file
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    """Teardown the pytest environment"""
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, step, file, count=120, wait=0.5):
    """Compare router JSON output"""

    tgen = get_topogen()
    logger.info('Comparing router "%s" "%s" output', rname, command)
    reference = open("{}/{}/step{}/{}".format(CWD, rname, step, file)).read()
    expected = json.loads(reference)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergence with SRv6 TI-LFA
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            1,
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): check IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 1, "show_ipv6_route.ref"
        )


def test_isis_route_backup_step1():
    """
    Test that backup routes are correctly computed with SRv6 segment stacks.

    This is the key test that verifies:
    - Backup routes exist in 'show isis route backup'
    - SRv6 SIDs are correctly displayed for routes requiring segment steering
    - Routes within Ext-P-Space correctly show '-' (no SIDs needed)
    """
    logger.info("Test (step 1): check IS-IS backup routes with SRv6 SIDs")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show isis route backup json", 1, "show_isis_route_backup.ref"
        )


#
# Step 2
#
# Action(s):
# - Shutdown rt1's eth-rt2 interface to simulate link failure
#
# Expected changes:
# - RT1 loses adjacency with RT2 on eth-rt2
# - RT1's routes to RT2 and RT4 should reconverge via backup paths (through RT3)
# - TI-LFA backup paths should become primary paths
#
def test_isis_adjacencies_step2():
    logger.info("Test (step 2): check IS-IS adjacencies after link failure")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shutting down rt1's eth-rt2 interface")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
        interface eth-rt2
        shutdown
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            2,
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv6_step2():
    logger.info("Test (step 2): check IPv6 RIB after link failure - routes via backup")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 2, "show_ipv6_route.ref"
        )


def test_isis_route_backup_step2():
    """
    Test backup routes after primary link failure.

    After RT1's eth-rt2 interface goes down:
    - RT1 should have new backup routes via RT3
    - Backup routes should be recomputed for the new topology
    """
    logger.info("Test (step 2): check IS-IS backup routes after link failure")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show isis route backup json", 2, "show_isis_route_backup.ref"
        )


#
# Step 3
#
# Action(s):
# - Bring rt1's eth-rt2 interface back up
#
# Expected changes:
# - RT1 re-establishes adjacency with RT2 on eth-rt2
# - Routes should return to original paths with TI-LFA backup protection
#
def test_isis_adjacencies_step3():
    logger.info("Test (step 3): check IS-IS adjacencies after link restore")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Bringing up rt1's eth-rt2 interface")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
        interface eth-rt2
        no shutdown
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            3,
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv6_step3():
    logger.info("Test (step 3): check IPv6 RIB after link restore - routes back to normal")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 3, "show_ipv6_route.ref"
        )


def test_isis_route_backup_step3():
    """
    Test backup routes are restored after link comes back up.

    After RT1's eth-rt2 interface comes back up:
    - Backup routes should be recomputed to original state
    - This verifies the TI-LFA computation is triggered on topology changes
    """
    logger.info("Test (step 3): check IS-IS backup routes after link restore")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router_compare_json_output(
            rname, "show isis route backup json", 3, "show_isis_route_backup.ref"
        )


#
# Memory leak test template
#
def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
