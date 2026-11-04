#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
Move BGP neighbors that inherit BFD between peer-groups with the same BFD
profile, while they carry enough routes for the old peer to linger in the
Deleted state:

  - multihop eBGP over loopbacks (EDGE1 <-> EDGE2)
  - single-hop eBGP (SH1 <-> SH2)

After every move, and after deleting and re-adding a neighbor, bfdd on both
routers must still have the session Up and bgpd must agree with it.
"""

import os
import re
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd]

ROUTES = 20000

# r1 neighbor -> r2 neighbor, multihop
SESSIONS = {
    "10.254.0.2": ("10.254.0.1", True),
    "10.0.12.2": ("10.0.12.1", False),
}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_SHARP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bfd_peer(router, peer):
    for entry in json.loads(router.vtysh_cmd("show bfd peers json")):
        if entry.get("peer") == peer:
            return entry
    return None


def _check_converged(groups):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    summary = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
    for peer in SESSIONS:
        info = summary.get("peers", {}).get(peer, {})
        if info.get("state") != "Established":
            return "r1: {} is {}".format(peer, info.get("state"))
        if info.get("pfxRcd") != ROUTES:
            return "r1: {} pfxRcd {}".format(peer, info.get("pfxRcd"))

    for peer, (r2_peer, multihop) in SESSIONS.items():
        entry = _bfd_peer(r1, peer)
        if entry is None:
            return "r1: bfdd has no session for {}".format(peer)
        if entry.get("status") != "up" or entry.get("multihop") != multihop:
            return "r1: bfdd session {}: {}".format(peer, entry)

        entry = _bfd_peer(r2, r2_peer)
        if entry is None or entry.get("status") != "up":
            return "r2: bfdd session {}: {}".format(r2_peer, entry)

        neigh = json.loads(r1.vtysh_cmd("show bgp neighbors {} json".format(peer)))
        neigh = neigh.get(peer, {})
        if neigh.get("peerGroup") != groups[peer]:
            return "r1: {} peer-group {}, expected {}".format(
                peer, neigh.get("peerGroup"), groups[peer]
            )
        bfd = neigh.get("peerBfdInfo", {})
        if bfd.get("status") != "Up":
            return "r1: bgpd BFD status for {}: {}".format(peer, bfd)

        neigh = json.loads(r2.vtysh_cmd("show bgp neighbors {} json".format(r2_peer)))
        bfd = neigh.get(r2_peer, {}).get("peerBfdInfo", {})
        if bfd.get("status") != "Up":
            return "r2: bgpd BFD status for {}: {}".format(r2_peer, bfd)

    return None


def _expect_converged(msg, groups):
    test_func = functools.partial(_check_converged, groups)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "{}: {}".format(msg, result)


def _bgp_peer_count():
    output = get_topogen().gears["r1"].vtysh_cmd("show memory", daemon="bgpd")
    match = re.search(r"^BGP peer\s*:\s*(\d+)", output, re.M)
    return int(match.group(1)) if match else None


def _expect_stable(msg, groups, peers):
    """
    The old peer object is freed only after its routes are cleared: wait
    until r1 bgpd is back to the number of peer objects it had before the
    change, then check the session survived it.
    """
    _expect_converged(msg, groups)
    _, result = topotest.run_and_expect(_bgp_peer_count, peers, count=60, wait=1)
    assert result == peers, "{}: r1 bgpd has {} peer objects, expected {}".format(
        msg, result, peers
    )
    time.sleep(2)
    result = _check_converged(groups)
    assert result is None, "{} (after old peer freed): {}".format(msg, result)


def _r1_config(lines):
    """Apply lines under router bgp on r1 and return the prior peer count."""
    peers = _bgp_peer_count()
    assert peers, "r1: cannot read the BGP peer count from show memory"
    r1 = get_topogen().gears["r1"]
    r1.vtysh_cmd("\n".join(["configure terminal", "router bgp 65001"] + lines))
    return peers


def test_bgp_bfd_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Install {} routes on r2 and wait for BGP and BFD".format(ROUTES))
    tgen.gears["r2"].vtysh_cmd(
        "sharp install routes 10.100.0.0 nexthop 10.0.12.1 {}".format(ROUTES)
    )
    _expect_converged(
        "initial convergence", {"10.254.0.2": "EDGE1", "10.0.12.2": "SH1"}
    )


def test_bgp_bfd_peer_group_move():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Move neighbors EDGE1 -> EDGE2 and SH1 -> SH2")
    peers = _r1_config(
        [
            "no neighbor 10.254.0.2 peer-group EDGE1",
            "neighbor 10.254.0.2 peer-group EDGE2",
            "no neighbor 10.0.12.2 peer-group SH1",
            "neighbor 10.0.12.2 peer-group SH2",
        ]
    )
    _expect_stable(
        "after moving to EDGE2/SH2", {"10.254.0.2": "EDGE2", "10.0.12.2": "SH2"}, peers
    )

    step("Move neighbors back EDGE2 -> EDGE1 and SH2 -> SH1")
    peers = _r1_config(
        [
            "no neighbor 10.254.0.2 peer-group EDGE2",
            "neighbor 10.254.0.2 peer-group EDGE1",
            "no neighbor 10.0.12.2 peer-group SH2",
            "neighbor 10.0.12.2 peer-group SH1",
        ]
    )
    _expect_stable(
        "after moving back to EDGE1/SH1",
        {"10.254.0.2": "EDGE1", "10.0.12.2": "SH1"},
        peers,
    )


def test_bgp_bfd_neighbor_delete_readd():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Delete neighbors and re-add them into EDGE2/SH2")
    peers = _r1_config(
        [
            "no neighbor 10.254.0.2",
            "neighbor 10.254.0.2 peer-group EDGE2",
            "no neighbor 10.0.12.2",
            "neighbor 10.0.12.2 peer-group SH2",
        ]
    )
    _expect_stable(
        "after delete and re-add", {"10.254.0.2": "EDGE2", "10.0.12.2": "SH2"}, peers
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
