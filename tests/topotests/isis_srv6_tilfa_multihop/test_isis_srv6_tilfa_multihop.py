#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_srv6_tilfa_multihop.py
# Part of FRR/NetDEF Topology Tests
#
# Copyright (c) 2025 Free Mobile, Vincent Jardin
#

"""
test_isis_srv6_tilfa_multihop.py:

Test IS-IS TI-LFA with SRv6 multi-hop backup paths and segment stacks.

This test verifies that when a backup path requires traversing multiple
hops (P-node and Q-node), the correct SRv6 segment stack is computed.

Multi-hop TI-LFA Scenario:
- The RT4-RT5 direct link is removed from this topology
- This forces backup paths to go through RT6 for certain destinations
- Example: From RT4, backup to RT5 requires RT4->RT6->RT5 path
- This tests SRv6 segment stack computation with End SID (P-node)
  and End.X SID (Q-node adjacency)

Topology (modified - no direct RT4-RT5 link):

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
         |   RT4   |                     |   RT5   |
         | 4.4.4.4 |                     | 5.5.5.5 |
         |         |                     |         |
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
"""

import os
import sys
import time
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
from lib.srv6_helper import (
    get_kernel_srv6_routes,
    get_route_nexthop_info,
    check_ping6,
)

pytestmark = [pytest.mark.isisd]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}

# Store baseline routes from step 1 for path verification
baseline_routes = {}

# SRv6 locator and loopback mappings
LOCATORS = {
    "rt1": "fc00:0:1::/48",
    "rt2": "fc00:0:2::/48",
    "rt3": "fc00:0:3::/48",
    "rt4": "fc00:0:4::/48",
    "rt5": "fc00:0:5::/48",
    "rt6": "fc00:0:6::/48",
}

LOOPBACKS = {
    "rt1": "fc00:0:1::1",
    "rt2": "fc00:0:2::1",
    "rt3": "fc00:0:3::1",
    "rt4": "fc00:0:4::1",
    "rt5": "fc00:0:5::1",
    "rt6": "fc00:0:6::1",
}


def build_topo(tgen):
    """Build function"""

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
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

    # NOTE: RT4-RT5 direct link is intentionally removed in this test
    # to force multi-hop TI-LFA backup paths through RT6

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

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
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
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

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            1,
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): check IPv6 RIB with SRv6 TI-LFA backups")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 1, "show_ipv6_route.ref"
        )


def test_kernel_srv6_routes_step1():
    """Verify SRv6 routes are correctly installed in the Linux kernel."""
    logger.info("Test (step 1): verify SRv6 routes in kernel via iproute2")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router = tgen.gears[rname]
        routes = get_kernel_srv6_routes(router)
        local_locator = LOCATORS[rname]
        assert local_locator in routes, f"{rname}: local SID {local_locator} not in kernel"
        assert routes[local_locator].get("encap") == "seg6local", \
            f"{rname}: local SID should have seg6local encap"


def test_traffic_step1():
    """Verify data plane connectivity using ping6 tests."""
    logger.info("Test (step 1): verify traffic connectivity via ping6")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    for dest_name in ["rt2", "rt3", "rt4", "rt5", "rt6"]:
        dest_addr = LOOPBACKS[dest_name]
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)
        assert success, f"Ping from rt1 to {dest_name} failed:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")


def test_path_baseline_step1():
    """Capture baseline route nexthops for path change verification."""
    logger.info("Test (step 1): capture baseline route nexthops")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Capture RT1's routes to RT4 (will be affected by RT2's eth-sw1 shutdown)
    # Path: RT1 -> RT2 -> RT4 (via eth-sw1 to RT2)
    router = tgen.gears["rt1"]
    baseline_routes["rt1_to_rt4"] = get_route_nexthop_info(router, LOCATORS["rt4"])
    logger.info(f"RT1 -> RT4 baseline: {baseline_routes['rt1_to_rt4']}")

    # Verify baseline route uses eth-sw1 (via RT2)
    assert baseline_routes["rt1_to_rt4"]["dev"] == "eth-sw1", \
        f"RT1 -> RT4 should use eth-sw1 in normal state, got {baseline_routes['rt1_to_rt4']['dev']}"


#
# Step 2
#
# Action(s):
# -Shutdown rt2's eth-sw1 interface to simulate link failure
#
# Expected changes:
# -rt2 loses adjacency with rt1 and rt3 on eth-sw1
# -rt2's routes to rt1 and rt3 should reconverge via backup paths (through rt4)
# -TI-LFA backup paths should become primary paths
#
def test_isis_adjacencies_step2():
    logger.info("Test (step 2): check IS-IS adjacencies after link failure")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shutting down rt2's eth-sw1 interface")
    tgen.net["rt2"].cmd('vtysh -c "conf t" -c "interface eth-sw1" -c "shutdown"')

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
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

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 2, "show_ipv6_route.ref"
        )


def test_kernel_srv6_routes_step2():
    """Verify SRv6 routes in kernel after link failure."""
    logger.info("Test (step 2): verify SRv6 routes in kernel after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router = tgen.gears[rname]
        routes = get_kernel_srv6_routes(router)
        local_locator = LOCATORS[rname]
        assert local_locator in routes, f"{rname}: local SID missing after link failure"


def test_traffic_step2():
    """Verify traffic connectivity after link failure."""
    logger.info("Test (step 2): verify traffic connectivity after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    for dest_name in ["rt3", "rt4", "rt5", "rt6"]:
        dest_addr = LOOPBACKS[dest_name]

        # Retry ping to allow routes to converge after link failure
        max_retries = 10
        success = False
        output = ""
        for attempt in range(max_retries):
            success, output = check_ping6(router, dest_addr, count=3, timeout=5)
            if success:
                break
            logger.info(f"Ping attempt {attempt + 1}/{max_retries} failed, retrying...")
            time.sleep(1)

        assert success, f"Ping from rt1 to {dest_name} failed after link failure:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")


def test_path_changed_step2():
    """Verify routes still exist after link failure (path may change)."""
    logger.info("Test (step 2): verify routes exist after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify RT1 still has a route to RT4 after RT2's eth-sw1 goes down
    router = tgen.gears["rt1"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt4"])
    logger.info(f"RT1 -> RT4 after failure: {current_route}")

    # Route should exist (via and dev should not be None)
    assert current_route["via"] is not None, \
        f"RT1 -> RT4 route should exist after link failure"
    assert current_route["dev"] is not None, \
        f"RT1 -> RT4 should have an outgoing device"

    logger.info(f"Route exists: via={current_route['via']}, dev={current_route['dev']}")


#
# Step 3
#
# Action(s):
# -Bring rt2's eth-sw1 interface back up
#
# Expected changes:
# -rt2 re-establishes adjacencies with rt1 and rt3 on eth-sw1
# -Routes should return to original paths with TI-LFA backup protection
#
def test_isis_adjacencies_step3():
    logger.info("Test (step 3): check IS-IS adjacencies after link restore")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Bringing up rt2's eth-sw1 interface")
    tgen.net["rt2"].cmd('vtysh -c "conf t" -c "interface eth-sw1" -c "no shutdown"')

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
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

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", 3, "show_ipv6_route.ref"
        )


def test_kernel_srv6_routes_step3():
    """Verify SRv6 routes in kernel after link recovery."""
    logger.info("Test (step 3): verify SRv6 routes in kernel after link restore")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router = tgen.gears[rname]
        routes = get_kernel_srv6_routes(router)
        for other_rname, other_locator in LOCATORS.items():
            assert other_locator in routes, \
                f"{rname}: route to {other_rname} missing after link restore"


def test_traffic_step3():
    """Verify traffic connectivity after link recovery."""
    logger.info("Test (step 3): verify traffic connectivity after link restore")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    for dest_name in ["rt2", "rt3", "rt4", "rt5", "rt6"]:
        dest_addr = LOOPBACKS[dest_name]
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)
        assert success, f"Ping from rt1 to {dest_name} failed after link restore:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")


def test_path_restored_step3():
    """Verify route nexthops restored to baseline after link recovery."""
    logger.info("Test (step 3): verify route paths restored after link recovery")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # RT1's route to RT4 should be back to original path (via RT2)
    router = tgen.gears["rt1"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt4"])
    logger.info(f"RT1 -> RT4 after restore: {current_route}")

    baseline = baseline_routes.get("rt1_to_rt4", {})
    assert current_route["via"] == baseline.get("via"), \
        f"RT1 -> RT4 nexthop should be restored. " \
        f"Baseline: {baseline.get('via')}, Current: {current_route['via']}"
    assert current_route["dev"] == "eth-sw1", \
        f"RT1 -> RT4 should use eth-sw1 after restore, got {current_route['dev']}"

    logger.info(f"Path restored: via={current_route['via']}, dev={current_route['dev']}")


#
# Step 4
#
# Verify IS-IS route output with SRv6 segment stacks
# Since RT4-RT5 direct link is removed, backup paths to certain destinations
# require multi-hop TI-LFA with SRv6 segment stacks containing:
# - End SID for P-node (intermediate node)
# - End.X SID for Q-node adjacency
#
def test_isis_route_step4():
    logger.info("Test (step 4): check IS-IS route with SRv6 segment stacks")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IS-IS routes on RT4 and RT5 specifically since they need multi-hop
    # backup paths due to the missing direct link
    for rname in ["rt4", "rt5"]:
        router_compare_json_output(
            rname, "show isis route level-1 json", 4, "show_isis_route.ref"
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
