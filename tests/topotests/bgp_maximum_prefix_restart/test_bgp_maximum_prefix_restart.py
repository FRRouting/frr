#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_maximum_prefix_restart.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# NVIDIA CORPORATION. All rights reserved.
#

"""
test_bgp_maximum_prefix_restart.py:

Test BGP maximum-prefix recovery scenarios:
1. Regular neighbor: set max-prefix below count -> session down
2. Regular neighbor: increase max-prefix above count -> session recovers
3. Peer-group member: set max-prefix below count -> session down
4. Peer-group member: increase max-prefix above count -> session recovers
5. Peer-group member: unset max-prefix (inherit) -> session recovers

Topology:
    r2 (sends 3 routes) ----> r1 (DUT) <---- r3 (sends 1 route)
                         (regular nbr)   (peer-group)
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r2 <-> r1 (regular neighbor test)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r3 <-> r1 (peer-group test)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_maximum_prefix_regular_neighbor():
    """
    Test maximum-prefix with regular neighbor (r1 <-> r2):
    - Session established initially (r2 sends 3 routes)
    - Set max-prefix to 1 on r1 (< 3 received) -> session goes down
    - Increase max-prefix to 5 on r1 (> 3 received) -> session recovers
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Verify initial BGP session is established between r1 and r2")

    def _bgp_session_established():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.1.2 json"))
        expected = {"192.168.1.2": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_established)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "BGP session failed to establish initially"

    step("Verify r1 has 3 routes in BGP table from r2")

    def _bgp_has_routes():
        output = json.loads(r1.vtysh_cmd("show ip bgp json"))
        routes = output.get("routes", {})
        r2_routes = sum(
            1 for prefix, data in routes.items() 
            if any(path.get("peerId") == "192.168.1.2" for path in data)
        )
        return r2_routes >= 3

    test_func = functools.partial(_bgp_has_routes)
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assert result, "r1 doesn't have 3 routes from r2"

    step("Set maximum-prefix to 1 on r1 (below received count of 3)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor 192.168.1.2 maximum-prefix 1
        """
    )

    step("Verify session goes down due to prefix count exceeded")

    def _bgp_session_prefix_exceeded():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.1.2 json"))
        expected = {
            "192.168.1.2": {
                "lastResetDueTo": "Reached received prefix count",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_prefix_exceeded)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Session didn't go down when hitting maximum-prefix"

    step("Increase maximum-prefix to 5 on r1 (above received count)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor 192.168.1.2 maximum-prefix 5
        """
    )

    step("Verify session recovers and becomes Established")
    test_func = functools.partial(_bgp_session_established)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Session failed to recover after increasing maximum-prefix"


def test_bgp_maximum_prefix_peer_group():
    """
    Test maximum-prefix with peer-group member (r1 <-> r3):
    - Session established initially (r3 sends 1 route)
    - Add 2 more routes on r3 (total 3 routes)
    - Set max-prefix to 1 on r1 peer-group -> session goes down
    - Increase max-prefix to 5 on r1 peer-group -> session recovers
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Verify initial BGP session is established between r1 and r3")

    def _bgp_session_established_r3():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.2.2 json"))
        expected = {"192.168.2.2": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_established_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "BGP session failed to establish initially"

    step("Add 2 more static routes on r3 (total 3 routes)")
    r3.vtysh_cmd(
        """
        configure terminal
        ip route 10.3.2.0/24 Null0
        ip route 10.3.3.0/24 Null0
        """
    )

    step("Verify r1 has 3 routes in BGP table from r3")

    def _bgp_has_routes_r3():
        output = json.loads(r1.vtysh_cmd("show ip bgp json"))
        routes = output.get("routes", {})
        r3_routes = sum(
            1 for prefix, data in routes.items() 
            if any(path.get("peerId") == "192.168.2.2" for path in data)
        )
        return r3_routes >= 3

    test_func = functools.partial(_bgp_has_routes_r3)
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assert result, "r1 doesn't have 3 routes from r3"

    step("Set maximum-prefix to 1 on r1 peer-group (below received count of 3)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor PG maximum-prefix 1
        """
    )

    step("Verify session goes down due to prefix count exceeded")

    def _bgp_session_prefix_exceeded_r3():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.2.2 json"))
        expected = {
            "192.168.2.2": {
                "lastResetDueTo": "Reached received prefix count",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_prefix_exceeded_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Session didn't go down when hitting maximum-prefix"

    step("Increase maximum-prefix to 5 on r1 peer-group (above received count)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor PG maximum-prefix 5
        """
    )

    step("Verify session recovers and becomes Established")
    test_func = functools.partial(_bgp_session_established_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert (
        result is None
    ), "Session failed to recover after increasing maximum-prefix on peer-group"


def test_bgp_maximum_prefix_peer_group_unset():
    """
    Test unsetting maximum-prefix on peer-group member:
    - Set max-prefix to 1 on r1 peer member (override) -> session goes down
    - Unset max-prefix on member (inherit from group with no limit) -> session recovers
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Remove peer-group maximum-prefix first on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no neighbor PG maximum-prefix
        """
    )

    # Wait for session to be established
    def _bgp_session_established_r3():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.2.2 json"))
        expected = {"192.168.2.2": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_established_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "BGP session failed to establish"

    step("Set maximum-prefix to 1 on r1 peer (override peer-group)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor 192.168.2.2 maximum-prefix 1
        """
    )

    step("Verify session goes down")

    def _bgp_session_prefix_exceeded_r3():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.2.2 json"))
        expected = {
            "192.168.2.2": {
                "lastResetDueTo": "Reached received prefix count",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_session_prefix_exceeded_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Session didn't go down"

    step("Unset maximum-prefix on r1 peer (inherit from peer-group with no limit)")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no neighbor 192.168.2.2 maximum-prefix
        """
    )

    step("Verify session recovers")
    test_func = functools.partial(_bgp_session_established_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Session failed to recover after unsetting maximum-prefix"


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
