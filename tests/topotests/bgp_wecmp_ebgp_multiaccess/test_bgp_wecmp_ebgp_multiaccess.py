#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test link-bandwidth WECMP per-peer adjustment in EBGP multiaccess topology.

Topology:

   r2 (65002, 192.168.0.2)
   r3 (65003, 192.168.0.3)  -- announces 10.100.0.0/24 with LB=100 Mbps
   r5 (65003, 192.168.0.5)  -- announces 10.100.0.0/24 with LB=200 Mbps
    |
    +--- LAN (192.168.0.0/24) --- r1 (65001) --- P2P (10.0.14.0/30) --- r4 (65004)

r1 receives two equal-cost paths for 10.100.0.0/24 from r3 and r5 (same AS
65003, same prefix) and performs ECMP.  Cumulative bandwidth = 300 Mbps.

r2 is on the same LAN as r3 and r5 (multiaccess): r1 passes the best path
with its original third-party nexthop and original per-path link-bandwidth.

r4 is on a different subnet (non-multiaccess): r1 substitutes its own
nexthop (10.0.14.1) and sets the cumulative link-bandwidth (300 Mbps).

Note on suppress-duplicate: the cumulative bandwidth is computed per-peer in
bpacket_reformat_for_peer() and is not reflected in the shared update-group
attribute (attr).  bgp_adj_out tracks cum_bw separately and includes it in the
suppress-duplicate comparison so that WECMP changes trigger an update to r4
even when attr is unchanged.
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

# 100 Mbps + 200 Mbps in bytes/sec (IEEE float encoded in link-bandwidth)
LB_R3 = 100  # Mbps
LB_R5 = 200  # Mbps
LB_CUM = LB_R3 + LB_R5  # 300 Mbps cumulative


def build_topo(tgen):
    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)

    # Shared LAN: r1, r2, r3, r5
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])
    s1.add_link(tgen.gears["r3"])
    s1.add_link(tgen.gears["r5"])

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


def _peer_linkbw(router, prefix, expected_nh, expected_bw_mbps):
    """Check nexthop and link-bandwidth (in Mbps) on the received route."""
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
    ecomm = p.get("extendedCommunity", {}).get("string", "")
    if not ecomm:
        return "no extendedCommunity for {} on {}".format(prefix, router.name)
    # Link-bandwidth is in the extended community string as "LB:AS:bps"
    # where bps = Mbps * 125000 (bytes/sec)
    expected_bps = expected_bw_mbps * 125000
    bw_str = "LB:65001:{}".format(expected_bps)
    if bw_str not in ecomm:
        return "LB mismatch for {} on {}: got '{}' want '{}'".format(
            prefix, router.name, ecomm, bw_str
        )
    return None


def test_wecmp_multiaccess():
    """
    r3 and r5 announce 10.100.0.0/24 with LB=100M and LB=200M respectively.
    r1 performs ECMP; cumulative bandwidth = 300 Mbps.

    r2 (multiaccess): receives best path with original third-party nexthop
    (192.168.0.3 or 192.168.0.5) and original per-path link-bandwidth.

    r4 (non-multiaccess): receives best path with nexthop = 10.0.14.1 and
    cumulative link-bandwidth = 300 Mbps.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    for neighbor in ["192.168.0.2", "192.168.0.3", "192.168.0.5", "10.0.14.2"]:
        _, result = topotest.run_and_expect(
            functools.partial(_bgp_converged, r1, neighbor),
            None, count=60, wait=1,
        )
        assert result is None, "r1 session with {} not established".format(neighbor)

    # r2: multiaccess — original nexthop, original per-path bandwidth (100M or 200M)
    # The best path may be from r3 (100M) or r5 (200M); we accept either.
    def _r2_check():
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast 10.100.0.0/24 json")
        )
        paths = output.get("paths", [])
        if not paths:
            return "no paths for 10.100.0.0/24 on r2"
        p = paths[0]
        nexthops = p.get("nexthops", [])
        if not nexthops:
            return "no nexthops for 10.100.0.0/24 on r2"
        nh = nexthops[0].get("ip", "")
        if nh not in ("192.168.0.3", "192.168.0.5"):
            return "expected third-party nexthop on r2, got {}".format(nh)
        ecomm = p.get("extendedCommunity", {}).get("string", "")
        # The best path comes from r3 (100 Mbps) or r5 (200 Mbps);
        # the originating AS is 65003 in both cases.
        expected_lb_r3 = "LB:65003:{}".format(LB_R3 * 125000)
        expected_lb_r5 = "LB:65003:{}".format(LB_R5 * 125000)
        if expected_lb_r3 not in ecomm and expected_lb_r5 not in ecomm:
            return "r2 missing per-path bandwidth: got '{}', want {} or {}".format(
                ecomm, expected_lb_r3, expected_lb_r5
            )
        # Must NOT carry cumulative bandwidth with the router's AS
        cum_bps = LB_CUM * 125000
        if "LB:65001:{}".format(cum_bps) in ecomm:
            return "r2 got cumulative bandwidth {} — expected per-path only".format(
                LB_CUM
            )
        return None

    _, result = topotest.run_and_expect(_r2_check, None, count=30, wait=1)
    assert result is None, result

    # Wait until r1 has both paths (from r3 and r5) for 10.100.0.0/24
    def _r1_has_two_paths():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast 10.100.0.0/24 json")
        )
        paths = output.get("paths", [])
        if len(paths) < 2:
            return "r1 has only {} path(s) for 10.100.0.0/24".format(len(paths))
        return None

    _, result = topotest.run_and_expect(_r1_has_two_paths, None, count=30, wait=1)
    assert result is None, result


    # r4: non-multiaccess — r1's own nexthop, cumulative bandwidth = 300 Mbps
    _, result = topotest.run_and_expect(
        functools.partial(_peer_linkbw, r4, "10.100.0.0/24", "10.0.14.1", LB_CUM),
        None, count=30, wait=1,
    )
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
