#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_nexthop.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

"""
test_bgp_evpn_nexthop.py: Test EVPN eBGP next-hop preservation (Issue #16209)

This test validates that EVPN routes traversing eBGP spine switches preserve
the original VTEP next-hop address instead of having it rewritten to the
spine's link IP.

Topology:
    R1 (VTEP) ---- R2 (Spine) ---- R3 (VTEP)
       AS 65001     AS 65002     AS 65003
          eBGP          eBGP

Test validates:
1. BGP sessions establish between all routers
2. R1's EVPN routes reach R3 with next-hop = 10.0.0.1 (R1's loopback)
3. Next-hop is NOT rewritten to 192.168.23.2 (R2's link IP)

This tests the fix in peer_activate_af() that automatically sets
PEER_FLAG_NEXTHOP_UNCHANGED for EVPN eBGP peers.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build eBGP EVPN topology with spine

    Topology:
        R1 (eth0) ------- (eth0) R2 (eth1) ------- (eth0) R3
        192.168.12.1      192.168.12.2   192.168.23.2      192.168.23.3
        AS 65001          AS 65002                         AS 65003
    """

    # Create routers
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    # Create switches for connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth0")
    switch.add_link(tgen.gears["r2"], nodeif="eth0")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="eth1")
    switch.add_link(tgen.gears["r3"], nodeif="eth0")


def setup_module(mod):
    """Sets up the pytest environment"""

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """
    Assert that all BGP sessions have converged
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Wait for BGP sessions to establish on R1
    logger.info("Checking BGP session on R1 to R2")
    r1 = tgen.gears["r1"]
    expected = {
        "192.168.12.2": {
            "bgpState": "Established",
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 BGP session to R2 not established"
    assert result is None, assertmsg

    # Wait for BGP sessions to establish on R2
    logger.info("Checking BGP sessions on R2")
    r2 = tgen.gears["r2"]
    expected = {
        "192.168.12.1": {
            "bgpState": "Established",
        },
        "192.168.23.3": {
            "bgpState": "Established",
        },
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R2 BGP sessions not established"
    assert result is None, assertmsg

    # Wait for BGP session to establish on R3
    logger.info("Checking BGP session on R3 to R2")
    r3 = tgen.gears["r3"]
    expected = {
        "192.168.23.2": {
            "bgpState": "Established",
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R3 BGP session to R2 not established"
    assert result is None, assertmsg


def test_evpn_routes_received():
    """
    Test that EVPN routes are received on R3
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN routes on R3")
    r3 = tgen.gears["r3"]

    # Wait for EVPN routes to be received
    # We expect at least one route from R1 (Type-3 IMET route for VNI 100)
    def check_evpn_routes():
        output = r3.vtysh_cmd("show bgp l2vpn evpn json", isjson=True)
        if "numPrefix" in output and output["numPrefix"] > 0:
            return None
        return "No EVPN routes received"

    _, result = topotest.run_and_expect(check_evpn_routes, None, count=60, wait=1)
    assertmsg = "R3 did not receive any EVPN routes"
    assert result is None, assertmsg


def test_evpn_nexthop_preserved():
    """
    Test that EVPN next-hop from R1 is preserved on R3 (Issue #16209)

    This is the main test case. We verify that routes from R1 (via R2 spine)
    arrive at R3 with the original next-hop (10.0.0.1) instead of R2's
    link IP (192.168.23.2).

    Without the fix in peer_activate_af(), the next-hop would be rewritten
    by R2 because eBGP normally rewrites next-hop to its own address.

    With the fix, PEER_FLAG_NEXTHOP_UNCHANGED is automatically set for EVPN
    eBGP peers, preserving the VTEP loopback address.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN next-hop preservation on R3 (Issue #16209)")
    r3 = tgen.gears["r3"]

    def check_evpn_nexthop():
        output = r3.vtysh_cmd("show bgp l2vpn evpn json", isjson=True)
        logger.info("R3 EVPN routes: %s" % json.dumps(output, indent=2))

        # Check if we have routes and examine their next-hops
        if "numPrefix" not in output or output["numPrefix"] == 0:
            return "No EVPN routes to check"

        # Look for routes with RD from R1 (65001:100)
        # These should have next-hop 10.0.0.1 (R1's loopback), NOT 192.168.23.2
        for rd_key, rd_data in output.items():
            if rd_key in ["numPrefix", "totalPrefix"]:
                continue

            if not isinstance(rd_data, dict):
                continue

            # Check if this is from R1's RD
            if "65001:100" not in str(rd_key):
                continue

            # Examine the routes under this RD
            for route_key, route_data in rd_data.items():
                if not isinstance(route_data, dict):
                    continue

                paths = route_data.get("paths", [])
                for path in paths:
                    nexthops = path.get("nexthops", [])
                    for nh in nexthops:
                        ip = nh.get("ip", "")
                        # Next-hop should be 10.0.0.1, NOT 192.168.23.2
                        if ip == "192.168.23.2":
                            return (
                                "FAIL: Next-hop is 192.168.23.2 (R2 link IP) "
                                "instead of 10.0.0.1 (R1 loopback). "
                                "Issue #16209 fix not working."
                            )
                        if ip == "10.0.0.1":
                            logger.info(
                                "SUCCESS: Next-hop preserved as 10.0.0.1 (R1 loopback)"
                            )
                            return None

        return "Could not find routes from R1 (RD 65001:100) to verify next-hop"

    _, result = topotest.run_and_expect(check_evpn_nexthop, None, count=60, wait=1)
    assertmsg = "EVPN next-hop preservation failed: {}".format(result)
    assert result is None, assertmsg


def test_dump_evpn_info():
    """
    Dump EVPN information for debugging
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router = tgen.gears[rname]
        output = router.vtysh_cmd("show bgp l2vpn evpn", isjson=False)
        logger.info("==== {} show bgp l2vpn evpn".format(rname))
        logger.info(output)

        output = router.vtysh_cmd("show bgp l2vpn evpn summary", isjson=False)
        logger.info("==== {} show bgp l2vpn evpn summary".format(rname))
        logger.info(output)


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
