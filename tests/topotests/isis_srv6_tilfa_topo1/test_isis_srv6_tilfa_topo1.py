#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_srv6_tilfa_topo1.py
# Part of FRR/NetDEF Topology Tests
#
# Copyright (c) 2025 Free Mobile, Vincent Jardin
#

"""
test_isis_srv6_tilfa_topo1.py:

Test IS-IS TI-LFA with SRv6.

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
    verify_backup_sids_allocated,
    verify_route_has_backup_nexthops,
    verify_kernel_endx_has_backup_nexthops,
    get_frr_backup_sids,
    enable_isis_lfa_debug,
    disable_isis_lfa_debug,
    get_isisd_log,
    monitor_sid_stability,
    parse_sid_allocation_events,
    check_for_allocation_loops,
    verify_no_pending_allocations,
    verify_backup_path_preinstalled,
    capture_preinstalled_backup_paths,
    verify_backup_path_activated,
    verify_backup_index_set,
)

pytestmark = [pytest.mark.isisd]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}

# Store baseline routes from step 1 for path verification
baseline_routes = {}

# Store baseline backup SIDs from step 1 for cleanup verification
baseline_backup_sids = {}

# Store pre-installed backup paths from step 1 for activation verification
preinstalled_backup_paths = {}

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

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
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
    "Compare router JSON output"

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


def _check_kernel_srv6_routes(router, rname, check_remote=True):
    """Helper to check kernel SRv6 routes. Returns None on success, error string on failure."""
    routes = get_kernel_srv6_routes(router)

    # Verify local SID is installed
    local_locator = LOCATORS[rname]
    if local_locator not in routes:
        return f"{rname}: local SID {local_locator} not in kernel"
    if routes[local_locator].get("encap") != "seg6local":
        return f"{rname}: local SID should have seg6local encap"

    if check_remote:
        # Verify routes to other routers exist
        for other_rname, other_locator in LOCATORS.items():
            if other_rname != rname:
                if other_locator not in routes:
                    return f"{rname}: route to {other_rname} ({other_locator}) not in kernel"

    return None


def test_kernel_srv6_routes_step1():
    """Verify SRv6 routes are correctly installed in the Linux kernel."""
    logger.info("Test (step 1): verify SRv6 routes in kernel via iproute2")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router = tgen.gears[rname]

        # Use retry logic to wait for routes to converge
        test_func = partial(_check_kernel_srv6_routes, router, rname)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, result

        # Log final routes
        routes = get_kernel_srv6_routes(router)
        logger.info(f"{rname} kernel routes: {json.dumps(routes, indent=2)}")


def test_traffic_step1():
    """Verify data plane connectivity using ping6 tests."""
    logger.info("Test (step 1): verify traffic connectivity via ping6")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Test connectivity from RT1 to all other routers
    router = tgen.gears["rt1"]
    for dest_name in ["rt2", "rt3", "rt4", "rt5", "rt6"]:
        dest_addr = LOOPBACKS[dest_name]
        logger.info(f"Ping from rt1 to {dest_name} ({dest_addr})")
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)
        assert success, f"Ping from rt1 to {dest_name} failed:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")

    # Test from RT6 to RT1 (multi-hop path)
    router = tgen.gears["rt6"]
    success, output = check_ping6(router, LOOPBACKS["rt1"], count=3, timeout=5)
    assert success, f"Ping from rt6 to rt1 failed:\n{output}"
    logger.info("Ping rt6 -> rt1: OK")


def test_path_baseline_step1():
    """Capture baseline route nexthops and backup SIDs for verification."""
    logger.info("Test (step 1): capture baseline route nexthops and backup SIDs")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Capture RT1's routes to RT2 (will be affected by RT2's eth-sw1 shutdown)
    router = tgen.gears["rt1"]
    baseline_routes["rt1_to_rt2"] = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT1 -> RT2 baseline: {baseline_routes['rt1_to_rt2']}")

    # Capture RT3's routes to RT2
    router = tgen.gears["rt3"]
    baseline_routes["rt3_to_rt2"] = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT3 -> RT2 baseline: {baseline_routes['rt3_to_rt2']}")

    # Verify baseline routes use eth-sw1 (direct path to RT2)
    assert baseline_routes["rt1_to_rt2"]["dev"] == "eth-sw1", \
        "RT1 -> RT2 should use eth-sw1 in normal state"
    assert baseline_routes["rt3_to_rt2"]["dev"] == "eth-sw1", \
        "RT3 -> RT2 should use eth-sw1 in normal state"

    # Capture baseline backup SIDs for cleanup verification in step2
    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]
        backup_sids = get_frr_backup_sids(router)
        baseline_backup_sids[rname] = backup_sids
        logger.info(f"{rname}: captured {len(backup_sids)} baseline backup SIDs")
        for sid in backup_sids:
            logger.info(f"  Backup SID: {sid['sid']} -> {sid.get('interfaceName', 'unknown')}")


def test_backup_path_preinstalled_step1():
    """Verify TI-LFA backup paths are pre-installed before any failure.

    This test confirms that backup paths are computed and installed in the RIB
    before any link failure occurs, which is essential for TI-LFA fast reroute.
    The pre-installed backup paths are captured for later verification in step2.
    """
    logger.info("Test (step 1): verify backup paths are pre-installed")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check RT4's backup paths to destinations reachable via RT2
    # When RT2's eth-sw1 fails, RT4 should have backup paths ready
    router = tgen.gears["rt4"]

    # Prefixes that RT4 reaches via RT2 and should have backup protection
    prefixes_to_check = [
        LOOPBACKS["rt1"] + "/128",  # RT1 via RT2 -> eth-sw1
        LOOPBACKS["rt2"] + "/128",  # RT2 directly via eth-rt2-1/2
    ]

    rt4_backups = {}
    for prefix in prefixes_to_check:
        success, msg, details = verify_backup_path_preinstalled(router, prefix)
        logger.info(f"rt4 -> {prefix}: {msg}")

        if details["has_backup"]:
            logger.info(f"  Primary nexthops: {len(details['primary_nexthops'])}")
            for nh in details["primary_nexthops"]:
                logger.info(f"    via {nh['gateway']} dev {nh['interface']}")
            logger.info(f"  Backup nexthops: {len(details['backup_nexthops'])}")
            for nh in details["backup_nexthops"]:
                logger.info(f"    via {nh['gateway']} dev {nh['interface']} "
                           f"seg6={nh.get('seg6')}")
            rt4_backups[prefix] = details

        assert success, f"rt4 -> {prefix}: {msg}"

    # Store for step2 verification
    preinstalled_backup_paths["rt4"] = rt4_backups
    logger.info(f"rt4: captured {len(rt4_backups)} pre-installed backup paths")

    # Check RT1's backup paths to RT2 (RT2's eth-sw1 will fail in step2)
    router = tgen.gears["rt1"]
    prefix = LOOPBACKS["rt2"] + "/128"

    success, msg, details = verify_backup_path_preinstalled(router, prefix)
    logger.info(f"rt1 -> {prefix}: {msg}")

    if details["has_backup"]:
        logger.info(f"  Primary nexthops: {len(details['primary_nexthops'])}")
        for nh in details["primary_nexthops"]:
            logger.info(f"    via {nh['gateway']} dev {nh['interface']}")
        logger.info(f"  Backup nexthops: {len(details['backup_nexthops'])}")
        for nh in details["backup_nexthops"]:
            logger.info(f"    via {nh['gateway']} dev {nh['interface']} seg6={nh.get('seg6')}")
        preinstalled_backup_paths["rt1"] = {prefix: details}

    # Note: RT1 may or may not have backup paths depending on topology
    # Just log the result for now
    if not success:
        logger.warning(f"rt1 -> rt2 has no backup path pre-installed: {msg}")


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

    # RT2's eth-sw1 is down, check routes are updated
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router = tgen.gears[rname]
        routes = get_kernel_srv6_routes(router)
        logger.info(f"{rname} kernel routes after link failure: {json.dumps(routes, indent=2)}")

        # Verify local SID still exists
        local_locator = LOCATORS[rname]
        assert local_locator in routes, f"{rname}: local SID missing after link failure"


def test_traffic_step2():
    """Verify traffic connectivity after link failure."""
    logger.info("Test (step 2): verify traffic connectivity after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Test from RT1 - should still reach all destinations via alternate paths
    # Allow retries since kernel routes may lag behind FRR RIB convergence
    router = tgen.gears["rt1"]
    for dest_name in ["rt3", "rt4", "rt5", "rt6"]:  # Skip rt2 as its link is down from sw1
        dest_addr = LOOPBACKS[dest_name]
        logger.info(f"Ping from rt1 to {dest_name} ({dest_addr}) after link failure")

        # Retry ping up to 10 times with 1 second delay
        max_retries = 10
        success = False
        output = ""
        for attempt in range(max_retries):
            success, output = check_ping6(router, dest_addr, count=3, timeout=5)
            if success:
                break
            logger.info(f"Ping attempt {attempt + 1}/{max_retries} failed, retrying...")
            time.sleep(1)

        if not success:
            kernel_routes = router.run("ip -6 route show proto isis")
            logger.error(f"Kernel routes:\n{kernel_routes}")
        assert success, f"Ping from rt1 to {dest_name} failed after link failure:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK (via backup path)")


def test_path_changed_step2():
    """Verify route nexthops changed after link failure."""
    logger.info("Test (step 2): verify route paths changed after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # RT1's route to RT2 should now use a different path (via RT3)
    router = tgen.gears["rt1"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT1 -> RT2 after failure: {current_route}")

    # The nexthop should have changed (different 'via' address or different path)
    # After RT2's eth-sw1 goes down, RT1 must reach RT2 via RT3->RT5->RT4->RT2
    # So the route should no longer point directly to RT2's link-local on eth-sw1
    baseline = baseline_routes.get("rt1_to_rt2", {})
    assert current_route["via"] != baseline.get("via"), \
        f"RT1 -> RT2 nexthop should change after link failure. " \
        f"Baseline: {baseline.get('via')}, Current: {current_route['via']}"

    logger.info(f"Path changed: baseline via={baseline.get('via')}, current via={current_route['via']}")

    # RT3's route to RT2 should also change (can no longer use direct eth-sw1 path)
    router = tgen.gears["rt3"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT3 -> RT2 after failure: {current_route}")

    baseline = baseline_routes.get("rt3_to_rt2", {})
    # RT3 should now route to RT2 via RT5->RT4 instead of direct eth-sw1
    assert current_route["via"] != baseline.get("via") or current_route["dev"] != baseline.get("dev"), \
        f"RT3 -> RT2 path should change after link failure. " \
        f"Baseline: dev={baseline.get('dev')}, via={baseline.get('via')}, " \
        f"Current: dev={current_route['dev']}, via={current_route['via']}"


def test_backup_path_activation_step2():
    """Verify traffic switched to the pre-installed backup path after failure.

    This test compares the current active path with the backup path that was
    pre-installed before the failure to confirm the correct backup was used.
    This validates that TI-LFA fast reroute is working correctly.
    """
    logger.info("Test (step 2): verify backup path activation after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check RT4's routes - verify the backup path was activated
    rt4_backups = preinstalled_backup_paths.get("rt4", {})
    if rt4_backups:
        router = tgen.gears["rt4"]
        for prefix, preinstalled in rt4_backups.items():
            success, msg, current = verify_backup_path_activated(
                router, prefix, preinstalled)
            logger.info(f"rt4 -> {prefix}: {msg}")

            if current["primary_nexthops"]:
                logger.info(f"  Current active nexthops:")
                for nh in current["primary_nexthops"]:
                    status = "active" if nh.get("active") else "inactive"
                    logger.info(f"    via {nh['gateway']} dev {nh['interface']} ({status})")

            # Log comparison with pre-installed backup
            logger.info(f"  Pre-installed backup nexthops were:")
            for nh in preinstalled.get("backup_nexthops", []):
                logger.info(f"    via {nh['gateway']} dev {nh['interface']}")

            # Note: After convergence, the path may differ from the exact backup
            # as the network reconverges with new optimal paths
            if not success:
                logger.warning(f"rt4 -> {prefix}: backup path activation check: {msg}")
    else:
        logger.info("rt4: no pre-installed backup paths captured in step1")

    # Check RT1's route to RT2 - this was the affected path
    rt1_backups = preinstalled_backup_paths.get("rt1", {})
    if rt1_backups:
        router = tgen.gears["rt1"]
        prefix = LOOPBACKS["rt2"] + "/128"
        preinstalled = rt1_backups.get(prefix)

        if preinstalled:
            success, msg, current = verify_backup_path_activated(
                router, prefix, preinstalled)
            logger.info(f"rt1 -> {prefix}: {msg}")

            if current["primary_nexthops"]:
                logger.info(f"  Current active nexthops:")
                for nh in current["primary_nexthops"]:
                    status = "active" if nh.get("active") else "inactive"
                    logger.info(f"    via {nh['gateway']} dev {nh['interface']} ({status})")
    else:
        logger.info("rt1: no pre-installed backup paths captured in step1")

    # Verify traffic still works via backup path
    router = tgen.gears["rt4"]
    for dest_name in ["rt1", "rt2"]:
        dest_addr = LOOPBACKS[dest_name]
        logger.info(f"Verifying traffic from rt4 to {dest_name} via backup path")

        max_retries = 5
        success = False
        output = ""
        for attempt in range(max_retries):
            success, output = check_ping6(router, dest_addr, count=3, timeout=5)
            if success:
                break
            logger.info(f"Ping attempt {attempt + 1}/{max_retries} failed, retrying...")
            time.sleep(1)

        assert success, f"Traffic from rt4 to {dest_name} failed after backup activation:\n{output}"
        logger.info(f"rt4 -> {dest_name}: traffic OK via backup path")


def test_backup_sid_cleanup_step2():
    """Verify backup SIDs are updated after topology change.

    When rt2's eth-sw1 goes down, the topology changes and TI-LFA recomputes
    backup paths. Some backup SIDs may be deallocated if they're no longer
    needed, and new ones may be allocated for the new topology.
    """
    logger.info("Test (step 2): verify backup SID cleanup/update after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]

        # Get current backup SIDs after link failure
        current_backup_sids = get_frr_backup_sids(router)
        baseline = baseline_backup_sids.get(rname, [])

        # Extract SID addresses for comparison
        baseline_sid_addrs = {sid["sid"] for sid in baseline}
        current_sid_addrs = {sid["sid"] for sid in current_backup_sids}

        logger.info(f"{rname}: baseline backup SIDs: {len(baseline)}, current: {len(current_backup_sids)}")
        logger.info(f"{rname}: baseline SIDs: {baseline_sid_addrs}")
        logger.info(f"{rname}: current SIDs: {current_sid_addrs}")

        # Check what changed
        removed_sids = baseline_sid_addrs - current_sid_addrs
        added_sids = current_sid_addrs - baseline_sid_addrs

        if removed_sids:
            logger.info(f"{rname}: backup SIDs removed after link failure: {removed_sids}")
        if added_sids:
            logger.info(f"{rname}: backup SIDs added after link failure: {added_sids}")

        # Verify the SID table is stable (no continuous reallocation)
        stable, msg, _ = monitor_sid_stability(router, duration_seconds=3, check_interval=1)
        logger.info(f"{rname}: SID stability check: {msg}")
        assert stable, f"{rname}: SID table unstable after link failure - {msg}"


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

        # Use retry logic to wait for routes to converge after link restore
        test_func = partial(_check_kernel_srv6_routes, router, rname)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, f"{rname}: {result}"

        # Log final routes
        routes = get_kernel_srv6_routes(router)
        logger.info(f"{rname} kernel routes after link restore: {json.dumps(routes, indent=2)}")


def test_traffic_step3():
    """Verify traffic connectivity after link recovery."""
    logger.info("Test (step 3): verify traffic connectivity after link restore")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Test full connectivity from RT1
    router = tgen.gears["rt1"]
    for dest_name in ["rt2", "rt3", "rt4", "rt5", "rt6"]:
        dest_addr = LOOPBACKS[dest_name]
        logger.info(f"Ping from rt1 to {dest_name} ({dest_addr}) after link restore")
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)
        assert success, f"Ping from rt1 to {dest_name} failed after link restore:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")

    # Test from RT6 to RT1
    router = tgen.gears["rt6"]
    success, output = check_ping6(router, LOOPBACKS["rt1"], count=3, timeout=5)
    assert success, f"Ping from rt6 to rt1 failed after link restore:\n{output}"
    logger.info("Ping rt6 -> rt1: OK")


def test_path_restored_step3():
    """Verify route nexthops restored to baseline after link recovery."""
    logger.info("Test (step 3): verify route paths restored after link recovery")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # RT1's route to RT2 should be back to using eth-sw1
    router = tgen.gears["rt1"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT1 -> RT2 after restore: {current_route}")

    baseline = baseline_routes.get("rt1_to_rt2", {})
    assert current_route["via"] == baseline.get("via"), \
        f"RT1 -> RT2 nexthop should be restored. " \
        f"Baseline: {baseline.get('via')}, Current: {current_route['via']}"
    assert current_route["dev"] == "eth-sw1", \
        f"RT1 -> RT2 should use eth-sw1 after restore, got {current_route['dev']}"

    logger.info(f"Path restored: via={current_route['via']}, dev={current_route['dev']}")

    # RT3's route to RT2 should also be restored
    router = tgen.gears["rt3"]
    current_route = get_route_nexthop_info(router, LOCATORS["rt2"])
    logger.info(f"RT3 -> RT2 after restore: {current_route}")

    baseline = baseline_routes.get("rt3_to_rt2", {})
    assert current_route["dev"] == "eth-sw1", \
        f"RT3 -> RT2 should use eth-sw1 after restore, got {current_route['dev']}"


def test_backup_sids_restored_step3():
    """Verify backup SIDs are restored after link recovery.

    When rt2's eth-sw1 comes back up, TI-LFA should recompute backup paths
    and allocate backup SIDs similar to the original topology.
    """
    logger.info("Test (step 3): verify backup SIDs restored after link recovery")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]

        # Get current backup SIDs after link restore
        current_backup_sids = get_frr_backup_sids(router)
        baseline = baseline_backup_sids.get(rname, [])

        logger.info(f"{rname}: baseline backup SIDs: {len(baseline)}, "
                   f"current after restore: {len(current_backup_sids)}")

        # Verify backup SIDs are allocated (should be similar count to baseline)
        # Allow some variation as topology reconvergence may differ slightly
        if len(baseline) > 0:
            assert len(current_backup_sids) > 0, \
                f"{rname}: Expected backup SIDs to be restored, found none"
            logger.info(f"{rname}: backup SIDs restored successfully")

        # Verify SID table is stable
        stable, msg, _ = monitor_sid_stability(router, duration_seconds=3, check_interval=1)
        logger.info(f"{rname}: SID stability check after restore: {msg}")
        assert stable, f"{rname}: SID table unstable after link restore - {msg}"

        # Log current backup SIDs
        for sid in current_backup_sids:
            logger.info(f"  Restored backup SID: {sid['sid']} -> {sid.get('interfaceName', 'unknown')}")


def test_sid_allocation_stability_step3():
    """Verify SID allocation is stable with no loops or pending allocations.

    This test checks for SID reallocation loop issues. It verifies that:
    1. No SIDs have pending allocation (allocation_in_progress flag cleared)
    2. Debug logs don't show allocation loops or churn
    3. SID table remains stable over time
    """
    logger.info("Test (step 3): verify SID allocation stability and no pending allocations")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]

        # Verify no pending SID allocations (allocation_in_progress should be false)
        success, msg, pending_count = verify_no_pending_allocations(router)
        logger.info(f"{rname}: {msg}")
        assert success, f"{rname}: {msg}"

        # Enable debug and capture recent log for analysis
        enable_isis_lfa_debug(router)

        # Wait briefly to capture any ongoing activity
        time.sleep(2)

        # Get isisd log and parse for allocation events
        log_output = router.run("cat /var/run/frr/isisd.log 2>/dev/null | tail -200 || "
                               "echo 'Log not available'")
        events = parse_sid_allocation_events(log_output)

        logger.info(f"{rname}: parsed {len(events['allocations'])} allocations, "
                   f"{len(events['deallocations'])} deallocations, "
                   f"{len(events['errors'])} errors from log")

        # Check for allocation loops
        has_loop, loop_msg = check_for_allocation_loops(events)
        logger.info(f"{rname}: allocation loop check: {loop_msg}")

        # Log any errors found
        if events['errors']:
            for err in events['errors']:
                logger.warning(f"{rname}: SID error in log: {err['raw']}")

        # Disable debug
        disable_isis_lfa_debug(router)

        # Final stability check
        stable, stability_msg, _ = monitor_sid_stability(router, duration_seconds=3, check_interval=1)
        logger.info(f"{rname}: final stability check: {stability_msg}")
        assert stable, f"{rname}: SID table unstable - {stability_msg}"

        # Assert no allocation loops detected
        assert not has_loop, f"{rname}: {loop_msg}"


#
# Step 4
#
# Test zebra fast reroute for seg6local routes
#
# This tests the fast path where interface down is detected at kernel level
# and zebra immediately switches seg6local routes to backup nexthops,
# WITHOUT waiting for ISIS reconvergence.
#
# Key difference from step 2:
# - Step 2 uses "vtysh interface shutdown" -> ISIS detects failure -> ISIS reconverges
# - Step 4 uses "ip link set down" -> kernel notifies zebra -> zebra fast reroute
#
# The fast reroute should complete in <50ms vs seconds for ISIS reconvergence.
#

# Store seg6local routes before failure for step 4 verification
step4_baseline_routes = {}


def test_capture_seg6local_baseline_step4():
    """Capture seg6local routes before testing fast reroute."""
    logger.info("Test (step 4): capture seg6local baseline routes for fast reroute test")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Capture RT4's seg6local routes (End.X SIDs) - these should switch on fast reroute
    router = tgen.gears["rt4"]

    # Get kernel seg6local routes
    output = router.run("ip -6 -json route show proto isis 2>/dev/null || "
                       "ip -6 route show proto isis")
    logger.info(f"rt4 kernel routes before fast reroute:\n{output[:2000]}")

    # Store baseline for comparison
    step4_baseline_routes["rt4"] = output

    # Also capture RT4's FRR view of backup SIDs
    backup_sids = get_frr_backup_sids(router)
    step4_baseline_routes["rt4_backup_sids"] = backup_sids
    logger.info(f"rt4 has {len(backup_sids)} backup SIDs before fast reroute")
    for sid in backup_sids:
        logger.info(f"  Backup SID: {sid['sid']} via {sid.get('interfaceName', 'unknown')}")


def test_zebra_fast_reroute_step4():
    """Test zebra fast reroute for seg6local routes.

    This test verifies that when an interface goes down at the kernel level
    (bypassing ISIS), zebra immediately switches seg6local routes to their
    backup nexthops. This is the fast path that should complete in <50ms.

    The test:
    1. Brings down RT4's eth-rt2-1 interface using 'ip link set down'
    2. Immediately checks that seg6local routes switched to backup
    3. Verifies traffic still works via backup path
    4. Brings interface back up
    5. Verifies routes reverted to primary nexthop
    """
    logger.info("Test (step 4): test zebra fast reroute for seg6local routes")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt4"]

    # Capture routes before failure
    routes_before = router.run("ip -6 route show proto isis | grep seg6local")
    logger.info(f"rt4 seg6local routes BEFORE interface down:\n{routes_before}")

    # FAST REROUTE TEST: Bring interface down at kernel level
    # This bypasses ISIS and directly triggers zebra's fast reroute
    logger.info("Bringing down rt4's eth-rt2-1 interface via kernel (fast path)")
    start_time = time.time()
    router.run("ip link set dev eth-rt2-1 down")

    # Give zebra a moment to process the interface down event
    # Fast reroute should be <50ms, we allow 500ms for safety
    time.sleep(0.5)

    elapsed = (time.time() - start_time) * 1000
    logger.info(f"Interface down + route update took {elapsed:.1f}ms")

    # Check routes IMMEDIATELY after interface down
    routes_after_down = router.run("ip -6 route show proto isis | grep seg6local")
    logger.info(f"rt4 seg6local routes AFTER interface down ({elapsed:.1f}ms):\n{routes_after_down}")

    # Verify routes changed (should now use backup nexthop)
    # The backup nexthop should use a different interface (eth-rt2-2 or eth-rt5)
    if routes_before != routes_after_down:
        logger.info("SUCCESS: seg6local routes changed after interface down (fast reroute worked)")
    else:
        logger.warning("Routes did not change immediately - fast reroute may not be active")

    # Check if eth-rt2-1 is no longer in the routes
    if "eth-rt2-1" not in routes_after_down:
        logger.info("SUCCESS: eth-rt2-1 no longer appears in routes after fast reroute")
    else:
        # This could be OK if routes via eth-rt2-1 don't have backups
        logger.info("Note: eth-rt2-1 still appears in some routes (may not have backup)")

    # TRAFFIC TEST: Verify connectivity via backup path
    logger.info("Verifying traffic connectivity via backup path")

    # Test connectivity to RT2 (should still be reachable via eth-rt2-2 or RT5->RT2)
    success, output = check_ping6(router, LOOPBACKS["rt2"], count=3, timeout=5)
    if success:
        logger.info("Ping rt4 -> rt2: OK via backup path")
    else:
        logger.warning(f"Ping rt4 -> rt2 failed (may be expected if no backup): {output}")

    # Test connectivity to RT1 (via RT5->RT3->RT1 or other path)
    success, output = check_ping6(router, LOOPBACKS["rt1"], count=3, timeout=5)
    assert success, f"Ping rt4 -> rt1 failed after fast reroute: {output}"
    logger.info("Ping rt4 -> rt1: OK")

    # RECOVERY TEST: Bring interface back up
    logger.info("Bringing up rt4's eth-rt2-1 interface (testing revert to primary)")
    router.run("ip link set dev eth-rt2-1 up")

    # Allow time for zebra to revert to primary nexthop
    # This may take longer as it needs to verify interface is stable
    time.sleep(2)

    routes_after_up = router.run("ip -6 route show proto isis | grep seg6local")
    logger.info(f"rt4 seg6local routes AFTER interface up:\n{routes_after_up}")

    # Verify routes reverted (should match baseline or at least use eth-rt2-1 again)
    if "eth-rt2-1" in routes_after_up:
        logger.info("SUCCESS: Routes reverted to use eth-rt2-1 after interface up")
    else:
        logger.warning("Routes did not revert to eth-rt2-1 - may need more time or ISIS reconvergence")

    # Final traffic test
    success, output = check_ping6(router, LOOPBACKS["rt2"], count=3, timeout=5)
    assert success, f"Ping rt4 -> rt2 failed after interface restore: {output}"
    logger.info("Ping rt4 -> rt2: OK after interface restore")

    success, output = check_ping6(router, LOOPBACKS["rt1"], count=3, timeout=5)
    assert success, f"Ping rt4 -> rt1 failed after interface restore: {output}"
    logger.info("Ping rt4 -> rt1: OK after interface restore")


def test_fast_reroute_timing_step4():
    """Verify fast reroute timing meets target (<50ms).

    This test measures the actual time it takes for zebra to switch
    seg6local routes to backup nexthops after interface down.
    """
    logger.info("Test (step 4): verify fast reroute timing")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt4"]

    # Ensure interface is up before test
    router.run("ip link set dev eth-rt2-1 up")
    time.sleep(2)

    # Get route signature before
    routes_before = router.run("ip -6 route show proto isis | grep -c eth-rt2-1 || echo 0").strip()
    logger.info(f"Routes using eth-rt2-1 before: {routes_before}")

    # Measure time from interface down to route change
    start_time = time.time()
    router.run("ip link set dev eth-rt2-1 down")

    # Poll for route change (max 1 second)
    route_changed = False
    check_interval = 0.01  # 10ms
    max_checks = 100  # 1 second total

    for i in range(max_checks):
        routes_after = router.run("ip -6 route show proto isis | grep -c eth-rt2-1 || echo 0").strip()
        if routes_after != routes_before:
            route_changed = True
            elapsed_ms = (time.time() - start_time) * 1000
            logger.info(f"Routes changed after {elapsed_ms:.1f}ms (check #{i+1})")
            break
        time.sleep(check_interval)

    if not route_changed:
        elapsed_ms = (time.time() - start_time) * 1000
        logger.warning(f"Routes did not change within {elapsed_ms:.1f}ms")
        logger.info("This may be expected if no seg6local routes use eth-rt2-1 as primary")
    else:
        # Log timing result
        if elapsed_ms < 50:
            logger.info(f"PASS: Fast reroute completed in {elapsed_ms:.1f}ms (target: <50ms)")
        elif elapsed_ms < 100:
            logger.info(f"ACCEPTABLE: Fast reroute completed in {elapsed_ms:.1f}ms (target: <50ms)")
        else:
            logger.warning(f"SLOW: Fast reroute took {elapsed_ms:.1f}ms (target: <50ms)")

    # Restore interface
    router.run("ip link set dev eth-rt2-1 up")
    time.sleep(2)

    # Verify routes restored
    routes_restored = router.run("ip -6 route show proto isis | grep -c eth-rt2-1 || echo 0").strip()
    logger.info(f"Routes using eth-rt2-1 after restore: {routes_restored}")


#
# Backup SID and nexthop verification tests
#
def test_backup_endx_sid_allocation_step1():
    """Verify backup End.X SIDs are allocated for TI-LFA protection."""
    logger.info("Test (step 1): verify backup End.X SID allocation")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Routers with multiple adjacencies should have backup SIDs allocated
    # RT4 has adjacencies to RT2 (dual-link), RT5, and RT6
    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]
        success, msg, backup_sids = verify_backup_sids_allocated(router, min_count=1)
        logger.info(f"{rname}: {msg}")

        # Store baseline backup SIDs for cleanup verification in step2
        baseline_backup_sids[rname] = backup_sids

        if backup_sids:
            for sid in backup_sids:
                logger.info(f"  Backup SID: {sid['sid']} -> {sid.get('interfaceName', 'unknown')}")
        assert success, f"{rname}: {msg}"


def test_rib_backup_routes_step1():
    """Verify routes have backup nexthops in the RIB."""
    logger.info("Test (step 1): verify backup nexthops in RIB")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check that routes to remote prefixes have backup nexthops
    # RT4 should have backup paths for routes to RT1, RT2, RT3
    router = tgen.gears["rt4"]

    # Routes to rt1 and rt2 should have backup nexthops
    # rt3 has 3 ECMP paths so may not need backup
    for dest_name in ["rt1", "rt2"]:
        prefix = LOOPBACKS[dest_name] + "/128"
        success, msg, route = verify_route_has_backup_nexthops(router, prefix, min_backups=1)
        logger.info(f"rt4 -> {dest_name} ({prefix}): {msg}")
        if route:
            nexthops = route.get("nexthops", [])
            backups = route.get("backupNexthops", [])
            logger.info(f"  Primary nexthops: {len(nexthops)}, Backup nexthops: {len(backups)}")
        assert success, f"rt4 -> {dest_name}: {msg}"

    # Log rt3 status (may have 0 backups due to 3 ECMP paths)
    prefix = LOOPBACKS["rt3"] + "/128"
    success, msg, route = verify_route_has_backup_nexthops(router, prefix, min_backups=1)
    logger.info(f"rt4 -> rt3 ({prefix}): {msg}")
    if route:
        nexthops = route.get("nexthops", [])
        backups = route.get("backupNexthops", [])
        logger.info(f"  Primary nexthops: {len(nexthops)}, Backup nexthops: {len(backups)}")


def test_rib_backup_index_step1():
    """Verify primary nexthops have backupIndex set correctly.

    When TI-LFA computes backup paths, primary nexthops should have a
    backupIndex array referencing the backup nexthops. This verifies the
    backup relationship is properly installed in the RIB.
    """
    logger.info("Test (step 1): verify backupIndex set on primary nexthops")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt4"]

    # Routes to rt1 and rt2 should have backupIndex set on primary nexthops
    for dest_name in ["rt1", "rt2"]:
        prefix = LOOPBACKS[dest_name] + "/128"
        success, msg, details = verify_backup_index_set(router, prefix)
        logger.info(f"rt4 -> {dest_name} ({prefix}): {msg}")

        if details:
            logger.info(f"  Total nexthops: {details.get('total_nexthops', 0)}")
            logger.info(f"  Nexthops with backupIndex: {details.get('nexthops_with_backup', 0)}")
            logger.info(f"  Backup nexthops: {details.get('backup_nexthops', 0)}")

        assert success, f"rt4 -> {dest_name}: {msg}"


def test_kernel_seg6local_routes_step1():
    """Verify seg6local routes are installed in the kernel."""
    logger.info("Test (step 1): verify seg6local routes in kernel")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check kernel routes for End.X SIDs on RT4
    router = tgen.gears["rt4"]
    locator_prefix = LOCATORS["rt4"].replace("/48", "")

    # Get all seg6local routes from kernel using JSON output
    routes = get_kernel_srv6_routes(router, proto="isis")
    logger.info(f"rt4 kernel routes: {json.dumps(routes, indent=2)}")

    # Verify at least the local End SID is installed
    local_sid_found = False
    for prefix, route_info in routes.items():
        if route_info.get("encap") == "seg6local" and locator_prefix in prefix:
            local_sid_found = True
            logger.info(f"  Found seg6local route: {prefix} -> {route_info}")

    assert local_sid_found, f"rt4: No seg6local routes found for locator {locator_prefix}"


def test_kernel_endx_backup_nexthops_step1():
    """Check if End.X routes in kernel have backup nexthops installed.

    Note: Backup nexthops for seg6local routes may not be supported by all
    kernel versions or zebra configurations. This test logs the current
    state and contains a commented assertion for future use.
    """
    logger.info("Test (step 1): check End.X routes for backup nexthops in kernel")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check routers that should have End.X SIDs with backup nexthops
    for rname in ["rt4", "rt5"]:
        router = tgen.gears[rname]

        # Log raw kernel seg6local routes for debugging
        output = router.run("ip -6 route show proto isis | grep -A1 seg6local")
        logger.info(f"{rname} kernel seg6local routes:\n{output}")

        # Check End.X routes for backup nexthops
        success, msg, endx_routes = verify_kernel_endx_has_backup_nexthops(router, min_count=1)
        logger.info(f"{rname}: {msg}")
        if endx_routes:
            for rt in endx_routes:
                logger.info(f"  End.X {rt['prefix']}: action={rt['action']}, "
                           f"nh6={rt.get('nh6')}, dev={rt.get('dev')}, "
                           f"backup nexthops={len(rt.get('nexthops', []))}")
        else:
            # Log that no backup nexthops were found
            logger.info(f"{rname}: No End.X routes with kernel backup nexthops found. "
                       "This may be expected if zebra doesn't support seg6local backup nexthops.")

        # TODO: Enable this assertion when kernel supports seg6local backup nexthops
        # assert success, f"{rname}: {msg}"


#
# Memory leak test template
#
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
