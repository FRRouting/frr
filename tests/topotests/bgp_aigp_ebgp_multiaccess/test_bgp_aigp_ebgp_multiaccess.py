#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test AIGP metric handling for EBGP third-party nexthop (multiaccess) case.

Topology:

   r2 (65002, 192.168.0.2)
    |
    +--- LAN (192.168.0.0/24) --- r1 (65001) --- P2P (10.0.14.0/30) --- r4 (65004)
    |
   r3 (65003, 192.168.0.3)

r3 announces two prefixes to r1:

1. 10.3.0.0/32 (loopback, connected): nexthop = 192.168.0.3, AIGP = 100.
   r2 is on the same LAN as 192.168.0.3 (multiaccess) so r1 passes the
   original third-party nexthop and original AIGP = 100.
   r4 is on a different subnet (non-multiaccess) so r1 substitutes its own
   nexthop (10.0.14.1); igpmetric for 192.168.0.3 is 0 (connected), so
   AIGP = 100 + 0 = 100.

2. 10.100.0.0/24 (static, metric 10): r3 overrides the nexthop to 10.100.0.3
   via outbound route-map; AIGP = igp-metric = 10.
   r1 has a static route to 10.100.0.3 via 192.168.0.3 with metric 20, so
   igpmetric = 20.  Neither r2 nor r4 is multiaccess with 10.100.0.3, so
   r1 substitutes its own nexthop for both and adjusts AIGP = 10 + 20 = 30.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rname in ["r1", "r2", "r3", "r4"]:
        tgen.add_router(rname)

    # Shared LAN: r1, r2, r3
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])
    s1.add_link(tgen.gears["r3"])

    # P2P: r1 -- r4
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r1"])
    s2.add_link(tgen.gears["r4"])


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


def _bgp_converged(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neighbor)))
    expected = {neighbor: {"bgpState": "Established"}}
    return topotest.json_cmp(output, expected)


def _peer_aigp(router, prefix, expected_nh, expected_aigp):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    paths = output.get("paths", [])
    if not paths:
        return "no paths for {} on {}".format(prefix, router.name)
    p = paths[0]
    nexthops = p.get("nexthops", [])
    if not nexthops:
        return "no nexthops for {} on {}".format(prefix, router.name)
    nh = nexthops[0].get("ip", "")
    if nh != expected_nh:
        return "nexthop mismatch for {} on {}: got {} want {}".format(
            prefix, router.name, nh, expected_nh
        )
    aigp = p.get("aigpMetric")
    if aigp != expected_aigp:
        return "AIGP mismatch for {} on {}: got {} want {}".format(
            prefix, router.name, aigp, expected_aigp
        )
    return None


def test_bgp_aigp_multiaccess():
    """
    r3 announces 10.3.0.0/32 with nexthop = 192.168.0.3 and AIGP = 100.

    r2 (192.168.0.2) is multiaccess with the nexthop 192.168.0.3: r1
    preserves the third-party nexthop and passes AIGP unchanged = 100.

    r4 (10.0.14.2) is not multiaccess: r1 substitutes nexthop = 10.0.14.1
    and adjusts AIGP = 100 + igpmetric(192.168.0.3=0) = 100.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # Wait for sessions
    for neighbor in ["192.168.0.2", "192.168.0.3", "10.0.14.2"]:
        _, result = topotest.run_and_expect(
            functools.partial(_bgp_converged, r1, neighbor),
            None, count=60, wait=1,
        )
        assert result is None, "r1 session with {} not established".format(neighbor)

    # r2: multiaccess — third-party nexthop preserved, AIGP unchanged
    _, result = topotest.run_and_expect(
        functools.partial(_peer_aigp, r2, "10.3.0.0/32", "192.168.0.3", 100),
        None, count=30, wait=1,
    )
    assert result is None, result

    # r4: not multiaccess — nexthop = r1's P2P address, AIGP = 100 + 0 = 100
    _, result = topotest.run_and_expect(
        functools.partial(_peer_aigp, r4, "10.3.0.0/32", "10.0.14.1", 100),
        None, count=30, wait=1,
    )
    assert result is None, result


def test_bgp_aigp_nonmultiaccess_adjustment():
    """
    r3 announces 10.100.0.0/24 with nexthop overridden to 10.100.0.3 and
    AIGP = igp-metric = 10 (from r3's static route metric 10).

    r1 has a static route to 10.100.0.3 via 192.168.0.3 with metric 20,
    so igpmetric = 20 for that nexthop.

    Neither r2 nor r4 is multiaccess with 10.100.0.3, so r1 substitutes
    its own nexthop and adjusts AIGP = 10 + 20 = 30 for both peers.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # r2: not multiaccess with 10.100.0.3 — nexthop = r1's LAN address
    _, result = topotest.run_and_expect(
        functools.partial(_peer_aigp, r2, "10.100.0.0/24", "192.168.0.1", 30),
        None, count=30, wait=1,
    )
    assert result is None, result

    # r4: not multiaccess — nexthop = r1's P2P address
    _, result = topotest.run_and_expect(
        functools.partial(_peer_aigp, r4, "10.100.0.0/24", "10.0.14.1", 30),
        None, count=30, wait=1,
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
