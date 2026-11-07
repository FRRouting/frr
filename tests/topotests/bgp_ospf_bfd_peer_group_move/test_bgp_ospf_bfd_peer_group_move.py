#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
OSPF and BGP share one bfdd session to the same single-hop neighbor
(10.0.12.2 on r1-eth0). The BGP neighbor inherits BFD from a peer-group and
carries enough routes for the old peer object to linger in the Deleted state
while it is moved between peer-groups, or deleted and re-added.

After every step the test drops BFD packets on r2 and checks that both
ospfd and bgpd on r1 are notified: OSPF resets the adjacency and BGP is
dropped. r2 runs BFD for OSPF only and the BGP hold time is 30s, so a BGP
drop within a few seconds can only come from r1's bgpd acting on its own
BFD down notification.

zebra relays session updates to every BFD client, so while OSPF holds the
session bgpd keeps receiving them even if its own registration was lost.
The test therefore also removes BFD from OSPF and checks that bgpd alone
still holds the session in bfdd and is still notified.
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

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd, pytest.mark.ospfd]

ROUTES = 20000
PEER = "10.0.12.2"
OSPF_NBR = "10.254.0.2"
BFD_DROP = "iptables {} INPUT -p udp --dport 3784 -j DROP"


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
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_OSPF, None),
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


def _ospf_nbr(router, nbr):
    output = json.loads(router.vtysh_cmd("show ip ospf neighbor json"))
    entries = output.get("neighbors", {}).get(nbr, [])
    return entries[0] if entries else {}


def _ospf_full(router, nbr):
    return _ospf_nbr(router, nbr).get("nbrState", "").startswith("Full")


def _bgp_neighbor(router, peer):
    output = json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(peer)))
    return output.get(peer, {})


def _check_converged(group):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    neigh = _bgp_neighbor(r1, PEER)
    if neigh.get("bgpState") != "Established":
        return "r1: BGP {} is {}".format(PEER, neigh.get("bgpState"))
    if neigh.get("peerGroup") != group:
        return "r1: {} peer-group {}, expected {}".format(
            PEER, neigh.get("peerGroup"), group
        )
    pfx = neigh.get("addressFamilyInfo", {}).get("ipv4Unicast", {})
    if pfx.get("acceptedPrefixCounter") != ROUTES:
        return "r1: {} accepted {}".format(PEER, pfx.get("acceptedPrefixCounter"))
    bfd = neigh.get("peerBfdInfo", {})
    if bfd.get("status") != "Up":
        return "r1: bgpd BFD status for {}: {}".format(PEER, bfd)

    if not _ospf_full(r1, OSPF_NBR):
        return "r1: OSPF neighbor {} not Full".format(OSPF_NBR)

    for router, peer in ((r1, PEER), (r2, "10.0.12.1")):
        entry = _bfd_peer(router, peer)
        if entry is None or entry.get("status") != "up":
            return "{}: bfdd session {}: {}".format(router.name, peer, entry)

    return None


def _expect_converged(msg, group):
    test_func = functools.partial(_check_converged, group)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "{}: {}".format(msg, result)


def _check_clients_notified(dropped, start, ospf):
    r1 = get_topogen().gears["r1"]

    neigh = _bgp_neighbor(r1, PEER)
    if neigh.get("connectionsDropped", 0) <= dropped:
        return "r1: bgpd not notified, BGP {} connectionsDropped {}".format(
            PEER, neigh.get("connectionsDropped")
        )
    if ospf:
        # Only BFD is dropped, so the adjacency may already be Full again
        nbr = _ospf_nbr(r1, OSPF_NBR)
        elapsed = (time.time() - start) * 1000
        if nbr.get("nbrState", "").startswith("Full") and (
            nbr.get("upTimeInMsec", 0) > elapsed
        ):
            return "r1: ospfd not notified, OSPF neighbor {}: {}".format(OSPF_NBR, nbr)

    return None


def _expect_clients_notified(msg, group, ospf=True):
    """
    Drop BFD packets on r2 and check that the BFD clients on r1 get the
    down notification. Only BFD is dropped: OSPF hellos and BGP keepalives
    still flow, so neither session goes down on its own (BGP hold time 30s).
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    dropped = _bgp_neighbor(tgen.gears["r1"], PEER).get("connectionsDropped", 0)

    start = time.time()
    r2.cmd_raises(BFD_DROP.format("-I"))
    try:
        test_func = functools.partial(_check_clients_notified, dropped, start, ospf)
        _, result = topotest.run_and_expect(test_func, None, count=8, wait=0.5)
    finally:
        r2.cmd_raises(BFD_DROP.format("-D"))
    assert result is None, "{}: {}".format(msg, result)

    _expect_converged("{} (recovery)".format(msg), group)


def _r1_ospf_bfd(enable):
    prefix = "" if enable else "no "
    get_topogen().gears["r1"].vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "interface r1-eth0",
                prefix + "ip ospf bfd",
                prefix + "ip ospf bfd profile P1",
            ]
        )
    )


def _expect_session_kept_by_bgp(msg, group):
    """
    Remove BFD from OSPF on r1 so bgpd is the only client left, then check
    the bfdd session survives and bgpd is still notified.
    """
    r1 = get_topogen().gears["r1"]
    msg = "{} (bgpd only)".format(msg)

    _r1_ospf_bfd(False)
    try:
        time.sleep(3)
        entry = _bfd_peer(r1, PEER)
        assert (
            entry is not None and entry.get("status") == "up"
        ), "{}: r1: bfdd session {} after removing OSPF BFD: {}".format(
            msg, PEER, entry
        )
        _expect_clients_notified(msg, group, ospf=False)
    finally:
        _r1_ospf_bfd(True)
    _expect_converged("{} (OSPF BFD restored)".format(msg), group)


def _bgp_peer_count():
    output = get_topogen().gears["r1"].vtysh_cmd("show memory", daemon="bgpd")
    match = re.search(r"^BGP peer\s*:\s*(\d+)", output, re.M)
    return int(match.group(1)) if match else None


def _change_and_check(msg, lines, group):
    """
    Apply lines under router bgp on r1, wait for convergence and for the old
    peer object to be freed (bgpd back to the prior number of peer objects),
    then check both BFD clients still get notified and bgpd still holds
    the session on its own.
    """
    r1 = get_topogen().gears["r1"]
    peers = _bgp_peer_count()
    assert peers, "r1: cannot read the BGP peer count from show memory"

    r1.vtysh_cmd("\n".join(["configure terminal", "router bgp 65001"] + lines))

    _expect_converged(msg, group)
    _, result = topotest.run_and_expect(_bgp_peer_count, peers, count=60, wait=1)
    assert result == peers, "{}: r1 bgpd has {} peer objects, expected {}".format(
        msg, result, peers
    )
    time.sleep(2)
    _expect_clients_notified(msg, group)
    _expect_session_kept_by_bgp(msg, group)


def test_bgp_ospf_bfd_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Install {} routes on r2 and wait for OSPF, BGP and BFD".format(ROUTES))
    tgen.gears["r2"].vtysh_cmd(
        "sharp install routes 10.100.0.0 nexthop 10.0.12.1 {}".format(ROUTES)
    )
    _expect_converged("initial convergence", "SH1")

    step("Both BFD clients are notified before any change")
    _expect_clients_notified("initial", "SH1")
    _expect_session_kept_by_bgp("initial", "SH1")


def test_bgp_ospf_bfd_peer_group_move():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Move the BGP neighbor SH1 -> SH2")
    _change_and_check(
        "after moving to SH2",
        [
            "no neighbor {} peer-group SH1".format(PEER),
            "neighbor {} peer-group SH2".format(PEER),
        ],
        "SH2",
    )

    step("Move the BGP neighbor back SH2 -> SH1")
    _change_and_check(
        "after moving back to SH1",
        [
            "no neighbor {} peer-group SH2".format(PEER),
            "neighbor {} peer-group SH1".format(PEER),
        ],
        "SH1",
    )


def test_bgp_ospf_bfd_neighbor_delete_readd():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Delete the BGP neighbor and re-add it into SH2")
    _change_and_check(
        "after delete and re-add",
        ["no neighbor {}".format(PEER), "neighbor {} peer-group SH2".format(PEER)],
        "SH2",
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
