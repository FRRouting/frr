#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Samsung R&D Institute India
#
# Author: Sri Mohan <sri.mohan@samsung.com>
#

"""
Test RFC 4271 Section 5.1.3 enforcement: A route originated by a BGP speaker
SHALL NOT be advertised to a peer using an address of that peer as NEXT_HOP.

Topology:
    R2 (AS65002) --- R3 (AS65002) --- R4 (AS65002)
    (originates      (IBGP transit    (IBGP receiver
     203.0.113.1/32   with route-map   - should NOT
     via connected)   nexthop peer)    receive route)

R2 has a route-map with "set ip next-hop peer-address" which would incorrectly
set the next-hop to R3's own address (10.0.0.3). The RFC 4271 fix detects this
and corrects the next-hop to R2's address (10.0.0.2).

This test verifies:
1. R3 receives the route with next-hop = 10.0.0.2 (R2's address, NOT R3's)
2. R3 does NOT advertise the IBGP-learned route to R4 (split-horizon)
3. R4 does NOT receive the route
"""

import os
import sys
import json
import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    """
    Build the topology for the test:
    - R2 -- R3 (IBGP peering)
    - R3 -- R4 (IBGP peering)
    """
    for routern in range(2, 5):
        tgen.add_router("r{}".format(routern))

    # R2 -- R3 link (IBGP)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # R3 -- R4 link (IBGP)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ipv4_nexthop_peer_self():
    """
    Test RFC 4271 Section 5.1.3: Next-hop shall not be set to receiving peer's address.

    Verifies that:
    1. R2 originates route 203.0.113.1/32 (via redistribute connected)
    2. R2 has route-map with "set ip next-hop peer-address"
    3. R3 receives route with next-hop = 10.0.0.2 (R2's address, corrected by fix)
       NOT 10.0.0.3 (R3's own address which would cause blackhole)
    4. R3 does NOT advertise the IBGP-learned route to R4 (split-horizon)
    5. R4 does NOT receive the route
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # Test 1: Verify BGP sessions are established
    def _bgp_converge():
        for router in [r2, r3, r4]:
            output = json.loads(router.vtysh_cmd("show ip bgp summary json"))
            if "ipv4Unicast" not in output:
                return False
        return True

    _, result = topotest.run_and_expect(_bgp_converge, True, count=60, wait=0.5)
    assert result is True, "BGP did not converge on all routers"

    # Test 2: Verify R2 has originated the route (locally via connected redistribute)
    def _r2_has_originated_route():
        output = json.loads(r2.vtysh_cmd("show ip bgp 203.0.113.1/32 json"))
        if "paths" not in output:
            return False
        if len(output["paths"]) == 0:
            return False
        # Route should be locally originated
        return output["paths"][0].get("valid", False)

    _, result = topotest.run_and_expect(_r2_has_originated_route, True, count=60, wait=0.5)
    assert result is True, "R2 did not originate route 203.0.113.1/32"

    # Test 3: Verify R3 received route with next-hop = R2's address (10.0.0.2)
    # This is the KEY test for RFC 4271 Section 5.1.3 nexthop-self-peer fix.
    # Without the fix, the route-map "set ip next-hop peer-address" would cause
    # the next-hop to be 10.0.0.3 (R3's own address) - a blackhole!
    # With the fix, it's corrected to 10.0.0.2 (R2's address).
    def _r3_has_route_with_nexthop_r2():
        output = json.loads(r3.vtysh_cmd("show ip bgp 203.0.113.1/32 json"))
        if "paths" not in output:
            return False
        if len(output["paths"]) == 0:
            return False
        # Check that nexthop is R2's address (10.0.0.2), NOT R3's own address (10.0.0.3)
        nexthop = output["paths"][0].get("nexthops", [{}])[0].get("ip", "")
        return nexthop == "10.0.0.2"

    _, result = topotest.run_and_expect(_r3_has_route_with_nexthop_r2, True, count=60, wait=0.5)
    assert result is True, "R3 received route with next-hop = R3's own address (RFC 4271 violation - blackhole!)"

    # Test 4: Verify R3 does NOT advertise the route to R4 (split-horizon)
    def _r3_not_advertise_to_r4():
        output = json.loads(r3.vtysh_cmd("show ip bgp neighbor 10.0.1.4 advertised-routes json"))
        advertised_routes = output.get("advertisedRoutes", {})
        # Route should NOT be in advertised routes
        return "203.0.113.1/32" not in advertised_routes

    _, result = topotest.run_and_expect(_r3_not_advertise_to_r4, True, count=60, wait=0.5)
    assert result is True, "R3 incorrectly advertised IBGP-learned route to R4 (RFC 4271 split-horizon violation)"

    # Test 5: Verify R4 does NOT have the route (proving split-horizon works)
    def _r4_no_route():
        output = json.loads(r4.vtysh_cmd("show ip bgp 203.0.113.1/32 json"))
        # Should have no paths for this prefix
        paths = output.get("paths", [])
        return len(paths) == 0

    _, result = topotest.run_and_expect(_r4_no_route, True, count=60, wait=0.5)
    assert result is True, "R4 received route from R3 (IBGP-to-IBGP advertisement, RFC 4271 violation)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
