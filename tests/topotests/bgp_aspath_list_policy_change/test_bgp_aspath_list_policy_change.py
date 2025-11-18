#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_aspath_list_policy_change.py
#
# Copyright (c) 2025 by NVIDIA Corporation
#
"""
Test that AS-path access-list changes trigger automatic inbound route
re-evaluation without requiring manual 'clear ip bgp soft in'.

When an AS-path access-list used as an inbound filter is modified,
BGP should automatically re-evaluate routes and apply the new policy.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build topology"""
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    """Setup topology"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Teardown topology"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aspath_list_policy_change():
    """
    Test that modifying an AS-path access-list used as an inbound filter
    automatically triggers route re-evaluation.

    Steps:
    1. Configure AS-path access-list BLOCK_AS65002 to deny routes with AS 65002
    2. Apply it as inbound filter on r2 for neighbor r3
    3. Verify route from r3 (AS 65002) is blocked
    4. Change AS-path list to permit AS 65002
    5. Verify route automatically appears without manual clear
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    logger.info("Step 1: Configure AS-path access-list BLOCK_AS65002 to deny AS 65002")
    r2.vtysh_cmd(
        """
configure terminal
bgp as-path access-list BLOCK_AS65002 seq 10 deny _65002_
bgp as-path access-list BLOCK_AS65002 seq 20 permit .*
    """
    )

    logger.info("Step 2: Apply AS-path list as inbound filter on r2 for neighbor r3")
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65001
address-family ipv4 unicast
neighbor 192.168.2.2 filter-list BLOCK_AS65002 in
    """
    )

    # Wait for BGP to converge and verify route is blocked
    logger.info("Step 3: Verify route from r3 (AS 65002) is blocked")
    def _route_blocked():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        # Check that route 10.0.0.0/24 with AS 65002 is not present
        if "routes" in output:
            for route, paths in output["routes"].items():
                if route == "10.0.0.0/24":
                    for path in paths:
                        path_str = path.get("path", "")
                        if "65002" in path_str:
                            return "Route still present"
        return None

    test_func = functools.partial(_route_blocked)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Route with AS 65002 should be blocked but is present"

    logger.info("Step 4: Change AS-path list to permit AS 65002")
    r2.vtysh_cmd(
        """
configure terminal
bgp as-path access-list BLOCK_AS65002 seq 10 permit _65002_
    """
    )

    logger.info("Step 5: Verify route automatically appears without manual clear")
    # The route should automatically appear due to policy change notification
    def _route_appears():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        if "routes" in output:
            for route, paths in output["routes"].items():
                if route == "10.0.0.0/24":
                    for path in paths:
                        path_str = path.get("path", "")
                        if "65002" in path_str:
                            return None
        return "Route not found"

    test_func = functools.partial(_route_appears)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Route 10.0.0.0/24 with AS 65002 should appear automatically after policy change"

    logger.info("Test passed: Route automatically re-evaluated after AS-path list change")


def test_bgp_aspath_list_policy_change_peer_group():
    """
    Test that modifying an AS-path access-list used as an inbound filter
    on a peer-group automatically triggers route re-evaluation for all members.

    Steps:
    1. Create peer-group PG1 with AS-path filter
    2. Add neighbor to peer-group
    3. Verify routes are filtered
    4. Change AS-path list
    5. Verify routes automatically update for peer-group member
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    logger.info("Step 1: Create peer-group PG1 with AS-path filter")
    # First remove existing neighbor configuration
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65001
address-family ipv4 unicast
no neighbor 192.168.2.2 filter-list BLOCK_AS65002 in
    """
    )
    
    # Create peer-group and configure
    r2.vtysh_cmd(
        """
configure terminal
bgp as-path access-list PG_FILTER seq 10 deny _65002_
bgp as-path access-list PG_FILTER seq 20 permit .*
router bgp 65001
neighbor PG1 peer-group
address-family ipv4 unicast
neighbor PG1 filter-list PG_FILTER in
neighbor 192.168.2.2 peer-group PG1
    """
    )

    # Wait for convergence
    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        return None

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    logger.info("Step 2: Verify route is blocked")
    def _route_blocked():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        if "routes" in output:
            for route, paths in output["routes"].items():
                if route == "10.0.0.0/24":
                    for path in paths:
                        path_str = path.get("path", "")
                        if "65002" in path_str:
                            return "Route still present"
        return None

    test_func = functools.partial(_route_blocked)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Route with AS 65002 should be blocked"

    logger.info("Step 3: Change AS-path list to permit")
    r2.vtysh_cmd(
        """
configure terminal
bgp as-path access-list PG_FILTER seq 10 permit _65002_
    """
    )

    logger.info("Step 4: Verify route automatically appears for peer-group member")
    def _route_appears():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        if "routes" in output:
            for route, paths in output["routes"].items():
                if route == "10.0.0.0/24":
                    for path in paths:
                        path_str = path.get("path", "")
                        if "65002" in path_str:
                            return None
        return "Route not found"

    test_func = functools.partial(_route_appears)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)

    assert result is None, "Route 10.0.0.0/24 should appear automatically for peer-group member after policy change"

    logger.info("Test passed: Peer-group member routes automatically re-evaluated")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

