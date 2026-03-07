#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_allow_rp.py
#
# Copyright (c) 2024
#

"""
test_pim_allow_rp.py: Test PIM allow-rp functionality

This test verifies that the 'ip pim allow-rp' command works correctly:
1. Without allow-rp: joins with mismatched RP are rejected
2. With allow-rp: joins with mismatched RP are accepted
3. With allow-rp rp-list: only RPs matching the prefix-list are accepted

Topology:
    r1 (LHR) ---- r2 (transit) ---- r3 (RP/source)

- r1: Receives IGMP, sends PIM joins with RP=r3 (10.254.0.3)
- r2: Transit router with DIFFERENT RP configured (10.254.0.99)
      This creates an RP mismatch scenario for testing allow-rp
- r3: The actual RP (10.254.0.3) and multicast source
"""

import os
import sys
import pytest
import time
from functools import partial

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    """Build function

    Topology:
        r1 (LHR) ---- r2 (transit) ---- r3 (RP)
    """

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1 <- sw1 -> r2
    # r1-eth0 <-> r2-eth0
    # 10.0.10.0/24
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])

    # r2 <- sw2 -> r3
    # r2-eth1 <-> r3-eth0
    # 10.0.20.0/24
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r3"])


def setup_module(mod):
    """Sets up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the integrated configuration file
    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()


def teardown_module():
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def check_pim_neighbor(router, expected_neighbor_ip):
    """Check if expected PIM neighbor exists"""
    output = router.vtysh_cmd("show ip pim neighbor json", isjson=True)
    for iface, neighbors in output.items():
        if isinstance(neighbors, dict):
            for neighbor_key, neighbor_data in neighbors.items():
                if expected_neighbor_ip == neighbor_key:
                    return None
    return "Neighbor {} not found".format(expected_neighbor_ip)


def check_upstream_state(router, group):
    """Check if upstream state exists for a group"""
    output = router.vtysh_cmd("show ip pim upstream json", isjson=True)
    if group in output:
        return None
    return "Upstream state for {} not found".format(group)


def check_no_upstream_state(router, group):
    """Check that upstream state does NOT exist for a group"""
    output = router.vtysh_cmd("show ip pim upstream json", isjson=True)
    if group not in output:
        return None
    return "Upstream state for {} should not exist".format(group)


def test_pim_neighbor_establish():
    """Ensure PIM neighbors are established"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Verify PIM neighbors are established")

    # Check r1 has r2 as neighbor
    test_func = partial(check_pim_neighbor, r1, "10.0.10.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 failed to establish PIM neighbor with r2"

    # Check r2 has r3 as neighbor
    test_func = partial(check_pim_neighbor, r2, "10.0.20.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 failed to establish PIM neighbor with r3"


def test_pim_rp_mismatch_without_allow_rp():
    """
    Test that without allow-rp, joins with mismatched RP are rejected.

    r1 has RP=10.254.0.3 (r3)
    r2 has RP=10.254.0.99 (different/non-existent)

    When r1 sends (*,G) join to r2, r2 should reject it because the RP
    in the join (10.254.0.3) doesn't match r2's configured RP (10.254.0.99).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Test RP mismatch without allow-rp - join should be rejected")

    # Add IGMP join-group on r1
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              ip igmp join-group 239.1.1.1
    """)

    # Wait for r1 to create upstream state
    test_func = partial(check_upstream_state, r1, "239.1.1.1")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r1 should have upstream state for 239.1.1.1"

    # Verify r2 does NOT have upstream state (join rejected due to RP mismatch)
    time.sleep(2)
    test_func = partial(check_no_upstream_state, r2, "239.1.1.1")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "r2 should NOT have upstream state without allow-rp"

    # Cleanup
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              no ip igmp join-group 239.1.1.1
    """)


def test_pim_allow_rp_accepts_join():
    """
    Test that with allow-rp enabled, joins with mismatched RP are accepted.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Test allow-rp accepts joins with mismatched RP")

    # Enable allow-rp on r2's interface facing r1
    r2.vtysh_cmd("""
        conf t
           interface r2-eth0
              ip pim allow-rp
    """)

    # Add IGMP join-group on r1
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              ip igmp join-group 239.1.1.2
    """)

    # Wait for r1 to create upstream state
    test_func = partial(check_upstream_state, r1, "239.1.1.2")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r1 should have upstream state for 239.1.1.2"

    # Verify r2 HAS upstream state (join accepted with allow-rp)
    test_func = partial(check_upstream_state, r2, "239.1.1.2")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r2 should have upstream state with allow-rp enabled"

    # Cleanup
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              no ip igmp join-group 239.1.1.2
    """)
    r2.vtysh_cmd("""
        conf t
           interface r2-eth0
              no ip pim allow-rp
    """)


def test_pim_allow_rp_plist_permit():
    """
    Test that allow-rp with a prefix-list accepts RPs that match the list.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Test allow-rp with prefix-list - RP in permit list")

    # Create prefix-list that permits r3's RP (10.254.0.3)
    r2.vtysh_cmd("""
        conf t
           ip prefix-list ALLOW_RP seq 5 permit 10.254.0.3/32
           interface r2-eth0
              ip pim allow-rp rp-list ALLOW_RP
    """)

    # Add IGMP join-group on r1
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              ip igmp join-group 239.1.1.3
    """)

    # Wait for r1 to create upstream state
    test_func = partial(check_upstream_state, r1, "239.1.1.3")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r1 should have upstream state for 239.1.1.3"

    # Verify r2 HAS upstream state (RP matches prefix-list)
    test_func = partial(check_upstream_state, r2, "239.1.1.3")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r2 should accept join when RP matches prefix-list"

    # Cleanup
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              no ip igmp join-group 239.1.1.3
    """)
    r2.vtysh_cmd("""
        conf t
           interface r2-eth0
              no ip pim allow-rp
           no ip prefix-list ALLOW_RP
    """)


def test_pim_allow_rp_plist_deny():
    """
    Test that allow-rp with a prefix-list rejects RPs that don't match the list.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Test allow-rp with prefix-list - RP not in permit list")

    # Create prefix-list that does NOT permit r3's RP (permits only 10.254.0.99)
    r2.vtysh_cmd("""
        conf t
           ip prefix-list DENY_RP seq 5 permit 10.254.0.99/32
           interface r2-eth0
              ip pim allow-rp rp-list DENY_RP
    """)

    # Add IGMP join-group on r1
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              ip igmp join-group 239.1.1.4
    """)

    # Wait for r1 to create upstream state
    test_func = partial(check_upstream_state, r1, "239.1.1.4")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "r1 should have upstream state for 239.1.1.4"

    # Verify r2 does NOT have upstream state (RP not in prefix-list)
    time.sleep(2)
    test_func = partial(check_no_upstream_state, r2, "239.1.1.4")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, "r2 should NOT accept join when RP doesn't match prefix-list"

    # Cleanup
    r1.vtysh_cmd("""
        conf t
           interface r1-eth0
              no ip igmp join-group 239.1.1.4
    """)
    r2.vtysh_cmd("""
        conf t
           interface r2-eth0
              no ip pim allow-rp
           no ip prefix-list DENY_RP
    """)


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
