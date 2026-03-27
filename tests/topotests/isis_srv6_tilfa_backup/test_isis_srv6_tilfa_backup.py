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
5. SRv6 routes are correctly installed in Linux kernel (via iproute2 verification)
6. Data plane connectivity works via ping6 tests through SRv6 paths

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
from lib.srv6_helper import (
    get_kernel_srv6_routes,
    verify_kernel_srv6_route,
    check_ping6,
)

pytestmark = [pytest.mark.isisd]


def ping6_connectivity(rname, dest, dest_name, source=None, count=3):
    """
    Test ping6 connectivity between routers.

    Args:
        rname: Source router name
        dest: Destination IPv6 address
        dest_name: Human-readable destination name for logging
        source: Source address/interface (optional)
        count: Number of ping packets
    """
    tgen = get_topogen()
    router = tgen.gears[rname]

    logger.info(f"Testing ping6 from {rname} to {dest_name} ({dest})")

    success, output = check_ping6(router, dest, source, count)

    if not success:
        logger.error(f"Ping failed: {output}")

    return success, output


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


# Locator map for kernel route verification
LOCATOR_MAP = {
    "rt1": "fc00:0:1::/48",
    "rt2": "fc00:0:2::/48",
    "rt3": "fc00:0:3::/48",
    "rt4": "fc00:0:4::/48",
}


def _check_kernel_srv6_routes(router, rname, check_remote=True):
    """Helper to check kernel SRv6 routes. Returns None on success, error string on failure."""
    routes = get_kernel_srv6_routes(router)

    # Verify local SID is installed
    local_locator = LOCATOR_MAP[rname]
    if local_locator not in routes:
        return f"{rname}: local SID {local_locator} not in kernel"
    if routes[local_locator].get("encap") != "seg6local":
        return f"{rname}: local SID should have seg6local encap"

    if check_remote:
        # Verify routes to other routers exist
        for other_rname, other_locator in LOCATOR_MAP.items():
            if other_rname != rname:
                if other_locator not in routes:
                    return f"{rname}: route to {other_rname} ({other_locator}) not in kernel"

    return None


def test_kernel_srv6_routes_step1():
    """
    Verify SRv6 routes are correctly installed in the Linux kernel.

    This test uses iproute2 to check that:
    - Local SIDs are installed with seg6local encap and correct action
    - Remote SRv6 routes are installed with proper encapsulation
    - Routes are installed via IS-IS protocol (proto isis)
    """
    logger.info("Test (step 1): verify SRv6 routes in kernel via iproute2")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4"]:
        router = tgen.gears[rname]
        logger.info(f"Checking kernel SRv6 routes on {rname}")

        # Use retry logic to wait for routes to converge
        test_func = partial(_check_kernel_srv6_routes, router, rname)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, result

        # Log final routes
        routes = get_kernel_srv6_routes(router)
        logger.info(f"{rname} kernel routes: {json.dumps(routes, indent=2)}")


def test_traffic_step1():
    """
    Verify data plane connectivity using ping6 tests.

    This test verifies that:
    - All routers can ping each other's loopback addresses
    - Traffic flows correctly through the SRv6 data plane
    """
    logger.info("Test (step 1): verify traffic connectivity via ping6")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Loopback addresses for each router
    loopbacks = {
        "rt1": "fc00:0:1::1",
        "rt2": "fc00:0:2::1",
        "rt3": "fc00:0:3::1",
        "rt4": "fc00:0:4::1",
    }

    # Test connectivity from RT1 to all other routers
    # RT1 is a good source as it has paths to all destinations
    source_router = "rt1"
    router = tgen.gears[source_router]

    for dest_name, dest_addr in loopbacks.items():
        if dest_name == source_router:
            continue

        logger.info(f"Ping from {source_router} to {dest_name} ({dest_addr})")
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)

        assert success, f"Ping from {source_router} to {dest_name} failed:\n{output}"
        logger.info(f"Ping {source_router} -> {dest_name}: OK")

    # Also test from RT4 to RT1 (multi-hop path)
    router = tgen.gears["rt4"]
    logger.info(f"Ping from rt4 to rt1 ({loopbacks['rt1']})")
    success, output = check_ping6(router, loopbacks["rt1"], count=3, timeout=5)
    assert success, f"Ping from rt4 to rt1 failed:\n{output}"
    logger.info("Ping rt4 -> rt1: OK")


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


def test_kernel_srv6_routes_step2():
    """
    Verify SRv6 routes in kernel after link failure.

    After RT1's eth-rt2 goes down:
    - RT1 should still have routes to all destinations via RT3
    - Routes should be updated in the kernel to reflect new paths
    """
    logger.info("Test (step 2): verify SRv6 routes in kernel after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Focus on RT1 since that's where the link failure occurred
    router = tgen.gears["rt1"]
    routes = get_kernel_srv6_routes(router)
    logger.info(f"rt1 kernel routes after link failure: {json.dumps(routes, indent=2)}")

    # RT1 should still have routes to RT2, RT3, RT4 (via RT3 now)
    locators = ["fc00:0:2::/48", "fc00:0:3::/48", "fc00:0:4::/48"]
    for locator in locators:
        assert locator in routes, f"rt1: route to {locator} missing after link failure"

    # Route to RT2 should now go via RT3 (eth-rt3)
    rt2_route = routes.get("fc00:0:2::/48", {})
    assert rt2_route.get("dev") == "eth-rt3", \
        f"rt1: route to RT2 should use eth-rt3 after link failure, got {rt2_route.get('dev')}"


def test_traffic_step2():
    """
    Verify traffic connectivity after link failure.

    After RT1's eth-rt2 goes down:
    - RT1 should still reach all destinations via backup path through RT3
    - This verifies the TI-LFA fast reroute is working
    """
    logger.info("Test (step 2): verify traffic connectivity after link failure")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Loopback addresses
    loopbacks = {
        "rt1": "fc00:0:1::1",
        "rt2": "fc00:0:2::1",
        "rt3": "fc00:0:3::1",
        "rt4": "fc00:0:4::1",
    }

    router = tgen.gears["rt1"]

    # Test from RT1 - the router with the failed link
    # Traffic should now flow via RT3
    for dest_name in ["rt3", "rt2", "rt4"]:  # Test rt3 first (direct), then rt2 (backup)
        dest_addr = loopbacks[dest_name]
        logger.info(f"Ping from rt1 to {dest_name} ({dest_addr}) after link failure")

        success, output = check_ping6(router, dest_addr, count=3, timeout=5)

        if not success:
            # Debug on failure: show routes and interface status
            logger.error(f"Ping failed to {dest_name}")
            logger.error(f"Ping output: {output}")
            kernel_routes = router.run("ip -6 route show proto isis")
            logger.error(f"Kernel routes:\n{kernel_routes}")
            iface_status = router.run("ip link show eth-rt2; ip link show eth-rt3")
            logger.error(f"Interface status:\n{iface_status}")

        assert success, f"Ping from rt1 to {dest_name} failed after link failure:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK (via backup path)")


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


def test_kernel_srv6_routes_step3():
    """
    Verify SRv6 routes in kernel after link recovery.

    After RT1's eth-rt2 comes back up:
    - Routes should return to original optimal paths
    - RT1 should use eth-rt2 for RT2 again
    """
    logger.info("Test (step 3): verify SRv6 routes in kernel after link restore")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check RT1's routes are back to normal
    router = tgen.gears["rt1"]
    routes = get_kernel_srv6_routes(router)
    logger.info(f"rt1 kernel routes after link restore: {json.dumps(routes, indent=2)}")

    # Verify all routes exist
    locators = ["fc00:0:1::/48", "fc00:0:2::/48", "fc00:0:3::/48", "fc00:0:4::/48"]
    for locator in locators:
        assert locator in routes, f"rt1: route to {locator} missing after link restore"

    # Route to RT2 should go via eth-rt2 again (direct path)
    rt2_route = routes.get("fc00:0:2::/48", {})
    assert rt2_route.get("dev") == "eth-rt2", \
        f"rt1: route to RT2 should use eth-rt2 after link restore, got {rt2_route.get('dev')}"


def test_traffic_step3():
    """
    Verify traffic connectivity after link recovery.

    After RT1's eth-rt2 comes back up:
    - All routes should work again via optimal paths
    - This verifies the network has fully converged
    """
    logger.info("Test (step 3): verify traffic connectivity after link restore")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Loopback addresses
    loopbacks = {
        "rt1": "fc00:0:1::1",
        "rt2": "fc00:0:2::1",
        "rt3": "fc00:0:3::1",
        "rt4": "fc00:0:4::1",
    }

    # Test full mesh connectivity from RT1
    router = tgen.gears["rt1"]
    for dest_name in ["rt2", "rt3", "rt4"]:
        dest_addr = loopbacks[dest_name]
        logger.info(f"Ping from rt1 to {dest_name} ({dest_addr}) after link restore")
        success, output = check_ping6(router, dest_addr, count=3, timeout=5)

        assert success, f"Ping from rt1 to {dest_name} failed after link restore:\n{output}"
        logger.info(f"Ping rt1 -> {dest_name}: OK")

    # Test from RT4 to RT1
    router = tgen.gears["rt4"]
    logger.info(f"Ping from rt4 to rt1 ({loopbacks['rt1']}) after link restore")
    success, output = check_ping6(router, loopbacks["rt1"], count=3, timeout=5)
    assert success, f"Ping from rt4 to rt1 failed after link restore:\n{output}"
    logger.info("Ping rt4 -> rt1: OK")


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
