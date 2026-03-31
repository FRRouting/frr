#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 NVIDIA Corporation
#               Donald Sharp
#
"""
Test static route cross-vrf nexthop resolution

This test verifies that:
1. A route in the same VRF should NOT be allowed to resolve via itself
   (preventing routing loops)
2. A route in different VRFs SHOULD be allowed to resolve via a prefix
   in another VRF even if the prefix is the same
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from time import sleep

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


def build_topo(tgen):
    """
    Build simple topology with two routers:
    r1 has two VRFs (vrf_a and vrf_b)
    """
    # Create routers
    tgen.add_router("r1")

    # Create a switch with a link to r1 and r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Setup VRFs on r1
    r1 = tgen.gears["r1"]
    r1.net.add_l3vrf("vrf_a", 100)
    r1.net.add_l3vrf("vrf_b", 200)

    # Load configurations
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_same_vrf_no_self_resolution():
    """
    Test that a route in the same VRF cannot resolve via itself.

    In vrf_a, we attempt to install:
    10.0.0.0/24 via 10.0.0.3

    This should fail because 10.0.0.3 is within 10.0.0.0/24.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking that route does NOT resolve via itself in same VRF")

    def _check_route_not_installed():
        """Check that the self-resolving route is NOT installed but valid route is"""
        output = r1.vtysh_cmd("show ip route vrf vrf_a 10.0.0.0/24 json")
        logger.info("show ip route vrf vrf_a 10.0.0.0/24: {}".format(output))

        route_data = json.loads(output)

        # The route should exist since we have a valid route configured
        if "10.0.0.0/24" not in route_data:
            # Route doesn't exist at all - this is acceptable
            return "No Route entry"

        route_entry = route_data["10.0.0.0/24"]

        # Check if there are any nexthops at all
        if not route_entry:
            return "No Route entry"

        # Collect all nexthops across all entries
        all_nexthops = []
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                all_nexthops.extend(nh_entry["nexthops"])

        if len(all_nexthops) != 2:
            return "Expected 2 nexthops for route 10.0.0.0/24, found {}".format(
                len(all_nexthops)
            )

        # Check each nexthop
        found_valid_nh = False
        found_invalid_nh = False

        for nh in all_nexthops:
            logger.info("Nexthop: {}".format(nh))
            nh_ip = nh.get("ip")
            is_active = nh.get("active", False)

            if nh_ip == "192.168.1.2":
                # This is the valid nexthop - should be active
                if not is_active:
                    return "Nexthop 192.168.1.2 should be active but is not"
                found_valid_nh = True
            elif nh_ip == "10.0.0.3":
                # This is the self-resolving nexthop - should NOT be active
                if is_active:
                    return "Nexthop 10.0.0.3 is active (should not be - routing loop)"
                found_invalid_nh = True

        if not found_valid_nh:
            return "Did not find expected valid nexthop 192.168.1.2"

        if not found_invalid_nh:
            return "Did not find expected invalid nexthop 10.0.0.3"

        # Everything is correct: 2 nexthops, valid one is active, invalid one is not
        return None

    test_func = functools.partial(_check_route_not_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_cross_vrf_resolution():
    """
    Test that a route in a different VRF CAN resolve via a prefix in another VRF.

    In vrf_a, we have an active route: 10.0.0.0/24 via 192.168.1.2
    In vrf_b, we install: 10.0.0.0/24 via 10.0.0.3 nexthop-vrf vrf_a

    This should succeed because the nexthop is in a different VRF.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking that route CAN resolve via cross-vrf nexthop")

    def _check_route_installed():
        """Check that the cross-vrf route IS installed and active"""
        output = r1.vtysh_cmd("show ip route vrf vrf_b 10.0.0.0/24 json")
        logger.info("show ip route vrf vrf_b 10.0.0.0/24: {}".format(output))

        route_data = json.loads(output)

        # The route should exist
        if "10.0.0.0/24" not in route_data:
            return "Route 10.0.0.0/24 not found in vrf_b"

        route_entry = route_data["10.0.0.0/24"]

        # Check that there is at least one active nexthop
        found_active = False
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                for nh in nh_entry["nexthops"]:
                    # Looking for nexthop 10.0.0.3 that goes via vrf_a
                    if nh.get("ip") == "10.0.0.3" and nh.get("active", False):
                        # Also check that it's using vrf_a for resolution
                        if nh.get("vrf") == "vrf_a":
                            found_active = True
                            break
            if found_active:
                break

        if not found_active:
            return "Route 10.0.0.0/24 via 10.0.0.3 vrf_a is not active"

        return None

    test_func = functools.partial(_check_route_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_cross_vrf_with_different_prefix():
    """
    Test cross-vrf resolution with a completely different prefix.

    In vrf_a, we have: 192.168.1.0/24 (connected)
    In vrf_b, we install: 172.16.0.0/16 via 192.168.1.10 nexthop-vrf vrf_a

    This should work fine as it's cross-vrf and different prefixes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Checking cross-vrf route with different prefix")

    def _check_route_installed():
        """Check that the cross-vrf route with different prefix is installed"""
        output = r1.vtysh_cmd("show ip route vrf vrf_b 172.16.0.0/16 json")
        logger.info("show ip route vrf vrf_b 172.16.0.0/16: {}".format(output))

        route_data = json.loads(output)

        if "172.16.0.0/16" not in route_data:
            return "Route 172.16.0.0/16 not found in vrf_b"

        route_entry = route_data["172.16.0.0/16"]

        found_active = False
        for nh_entry in route_entry:
            if "nexthops" in nh_entry:
                for nh in nh_entry["nexthops"]:
                    if nh.get("ip") == "192.168.1.10" and nh.get("active", False):
                        found_active = True
                        break
            if found_active:
                break

        if not found_active:
            return "Route 172.16.0.0/16 via 192.168.1.10 vrf_a is not active"

        return None

    test_func = functools.partial(_check_route_installed)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_vrf_teardown_cleanup():
    """
    Test that ECMP routes retain valid nexthops when a nexthop VRF goes down.

    Bug (pre-fix): static_cleanup_vrf() called static_uninstall_nexthop() per
    nexthop, which sent a ZAPI ADD including the cross-VRF nexthop (with its
    nh_vrf_id still valid) before marking it VRF_UNKNOWN.  Zebra stored the
    stale nexthop, which then appeared as an inactive entry in the RIB even
    after the VRF was gone.

    Fix: mark all affected nexthops VRF_UNKNOWN first (deregistering NHT),
    then do a single uninstall_path + install_path so the ZAPI ADD sent to
    zebra contains only the surviving nexthops.

    Design:
      The cross-VRF nexthop (9.9.9.9 in vrf_a) is resolved via a blackhole
      static route so that NHT reports it valid without needing any physical
      interface enslaved to vrf_a.  This is crucial: when vrf_a is torn down,
      the kernel sends RTM_DELLINK (no RTM_DELADDR, since no enslaved
      interfaces carry addresses that belong to vrf_a's routing table).
      Consequently no NEXTHOP_UPDATE is triggered for 9.9.9.9 before zebra
      sends ZEBRA_VRF_DELETE to staticd, keeping nh_valid=true at the moment
      static_cleanup_vrf_ids() fires.

      - Without fix: static_uninstall_nexthop() is called while nh_vrf_id is
        still valid and nh_valid=true, so the ZAPI ADD includes 9.9.9.9.
        Zebra stores it as an inactive nexthop; 9.9.9.9 appears in the RIB.
      - With fix: nh_vrf_id is set to VRF_UNKNOWN first; static_zebra_route_add()
        skips it, so the ZAPI ADD contains only 10.2.0.2. Zebra installs a
        new nhg without 9.9.9.9; the route shows only 10.2.0.2.

    Setup:
      - Add a blackhole route 9.9.9.9/32 in vrf_a so NHT resolves it as valid.
      - Add a dummy interface to vrf_b (10.2.0.1/24) for a resolvable local NH.
      - In vrf_b, install 10.3.0.0/24 with two nexthops at the same distance:
          9.9.9.9 nexthop-vrf vrf_a  (cross-VRF, resolved via blackhole)
          10.2.0.2                    (local to vrf_b, resolved via dummy_b)
      - Verify both nexthops are initially active.
      - Delete kernel vrf_a device then "no vrf vrf_a" to fire
        static_cleanup_vrf_ids() (two-step required: kernel deletion disables
        the VRF; FRR config deletion fires the full vrf_disable hook chain).
      - Verify 10.3.0.0/24 still has 10.2.0.2 active and 9.9.9.9 is
        completely absent (not even inactive).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Testing VRF teardown does not leave stale cross-VRF nexthop in RIB")

    # Install a blackhole route for 9.9.9.9/32 in vrf_a so that staticd's NHT
    # registration reports 9.9.9.9 as valid (blackhole nexthops are always
    # ACTIVE in zebra).  No physical interface needs to be enslaved to vrf_a
    # for this to work, which is the key to the test design (see docstring).
    r1.vtysh_cmd(
        """
configure terminal
ip route 9.9.9.9/32 blackhole vrf vrf_a
"""
    )

    # Add a dummy interface to vrf_b so 10.2.0.0/24 is connected there,
    # making 10.2.0.2 resolvable as a local nexthop in vrf_b.
    r1.run("ip link add dummy_b type dummy")
    r1.run("ip link set dummy_b master vrf_b")
    r1.run("ip link set dummy_b up")
    r1.run("ip addr add 10.2.0.1/24 dev dummy_b")

    # Configure ECMP route 10.3.0.0/24 in vrf_b with two nexthops:
    #   - 9.9.9.9 resolved in vrf_a (cross-VRF, via blackhole → always active)
    #   - 10.2.0.2 resolved locally in vrf_b (via connected 10.2.0.0/24 on dummy_b)
    r1.vtysh_cmd(
        """
configure terminal
ip route 10.3.0.0/24 9.9.9.9 nexthop-vrf vrf_a vrf vrf_b
ip route 10.3.0.0/24 10.2.0.2 vrf vrf_b
"""
    )

    def _check_both_nexthops_active():
        output = r1.vtysh_cmd("show ip route vrf vrf_b 10.3.0.0/24 json")
        logger.info("show ip route vrf vrf_b 10.3.0.0/24: {}".format(output))
        route_data = json.loads(output)
        if "10.3.0.0/24" not in route_data:
            return "Route 10.3.0.0/24 not found in vrf_b"
        active_nhs = []
        for nh_entry in route_data["10.3.0.0/24"]:
            for nh in nh_entry.get("nexthops", []):
                if nh.get("active", False):
                    active_nhs.append(nh.get("ip"))
        if len(active_nhs) < 2:
            return "Expected 2 active nexthops, found: {}".format(active_nhs)
        return None

    success, result = topotest.run_and_expect(
        _check_both_nexthops_active, None, count=30, wait=1
    )
    assert result is None, "Initial state check failed: {}".format(result)

    # Two-step VRF teardown to fire static_cleanup_vrf_ids():
    #
    # 1. Delete the kernel VRF device.  Because no physical interface is
    #    enslaved to vrf_a, the kernel sends only RTM_DELLINK (no
    #    RTM_DELADDR).  This avoids triggering a NEXTHOP_UPDATE for 9.9.9.9
    #    before static_cleanup_vrf_ids() fires, keeping nh_valid=true.
    #    zebra calls vrf_disable() here, which sends ZEBRA_VRF_DELETE to
    #    staticd and fires static_cleanup_vrf_ids().
    #
    # 2. "no vrf vrf_a" via vtysh — FRR only permits this after the kernel
    #    device is gone (VRF inactive).  This completes the FRR config removal.
    logger.info("Deleting kernel vrf_a device (no enslaved interfaces → no RTM_DELADDR)")
    r1.run("ip link delete vrf_a")

    logger.info("Removing FRR vrf_a config to complete teardown")
    r1.vtysh_cmd("configure terminal\nno vrf vrf_a\n")

    def _check_route_survives_with_local_nexthop():
        output = r1.vtysh_cmd("show ip route vrf vrf_b 10.3.0.0/24 json")
        logger.info(
            "show ip route vrf vrf_b 10.3.0.0/24 (after vrf_a deleted): {}".format(
                output
            )
        )
        route_data = json.loads(output)
        if "10.3.0.0/24" not in route_data:
            return "Route 10.3.0.0/24 removed from vrf_b (bug: valid nexthop lost)"
        active_nhs = []
        all_nhs = []
        for nh_entry in route_data["10.3.0.0/24"]:
            for nh in nh_entry.get("nexthops", []):
                all_nhs.append(nh.get("ip"))
                if nh.get("active", False):
                    active_nhs.append(nh.get("ip"))
        if "10.2.0.2" not in active_nhs:
            return "Nexthop 10.2.0.2 (vrf_b) not active after vrf_a teardown: {}".format(
                active_nhs
            )
        # With the fix, static_zebra_route_add() skips VRF_UNKNOWN nexthops,
        # so the ZAPI ADD after cleanup contains only 10.2.0.2; zebra installs
        # a new nhg without 9.9.9.9 and the stale nexthop is gone entirely.
        # Without the fix, the ADD is sent before nh_vrf_id is set to
        # VRF_UNKNOWN, so 9.9.9.9 is included with a stale VRF ID and
        # permanently appears in zebra as an inactive nexthop.
        if "9.9.9.9" in all_nhs:
            return (
                "Stale cross-VRF nexthop 9.9.9.9 still present (even inactive) "
                "after vrf_a teardown: {}".format(all_nhs)
            )
        return None

    success, result = topotest.run_and_expect(
        _check_route_survives_with_local_nexthop, None, count=30, wait=1
    )

    # Cleanup: remove test routes and dummy interface, then restore vrf_a
    # (kernel device + FRR config + interface binding) for subsequent tests.
    r1.vtysh_cmd(
        """
configure terminal
no ip route 10.3.0.0/24 9.9.9.9 nexthop-vrf vrf_a vrf vrf_b
no ip route 10.3.0.0/24 10.2.0.2 vrf vrf_b
"""
    )
    r1.run("ip link delete dummy_b")
    r1.run("ip link add vrf_a type vrf table 100")
    r1.run("ip link set vrf_a up")
    r1.vtysh_cmd("configure terminal\nvrf vrf_a\nexit-vrf\n")
    r1.run("ip link set r1-eth0 master vrf_a")
    r1.run("ip link set r1-eth0 up")

    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
