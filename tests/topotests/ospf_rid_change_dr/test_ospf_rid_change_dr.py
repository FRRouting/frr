#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_rid_change_dr.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Olasupo Okunaiya
#

"""
test_ospf_rid_change_dr.py: DR election must re-run when the OSPF
router-id changes on a broadcast network, without disturbing
point-to-point interfaces.

Changing the router-id resets each interface's self neighbor, which
clears the cached DR/BDR. On a multi-access (broadcast) segment the
DR/BDR are only recomputed by the interface state machine, so without a
re-election the interface keeps a DR of 0.0.0.0 and the DR re-originates
its Network-LSA with a Link State ID of 0.0.0.0. The re-election must be
limited to interfaces that actually elect a DR: a point-to-point
adjacency must not be flapped by the router-id change.

Topology:

   r2 --- (broadcast LAN: sw1) --- r1 --- (point-to-point) --- r3

r1 has the higher OSPF priority on the LAN and becomes the DR; r2 has
priority 0 so nothing else can trigger a re-election there. r1 has no
static router-id, so its router-id comes from zebra. Once everything is
Full, a loopback address is added on r1 (a loopback is preferred for the
router-id), which raises r1's router-id and is applied without an
interface reset. The test then verifies that the LAN DR and Network-LSA
are valid again and that the point-to-point adjacency to r3 was not
reset.
"""

import os
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

NEW_RID = "172.16.1.1"
DR_ADDR = "10.0.0.1"
R3_RID = "3.3.3.3"


def build_topo(tgen):
    "Build function"
    for n in (1, 2, 3):
        tgen.add_router("r%d" % n)
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])
    # r1-eth1 <-> r3-eth0 point-to-point link
    tgen.gears["r1"].add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_neighbors():
    tgen = get_topogen()
    nbr = tgen.gears["r1"].vtysh_cmd("show ip ospf neighbor json", isjson=True)
    return [n for entries in nbr.get("neighbors", {}).values() for n in entries]


def _p2p_neighbor():
    "Return r1's neighbor entry for r3 (the point-to-point peer), or None."
    for n in _r1_neighbors():
        if n.get("ifaceName", "").startswith("r1-eth1"):
            return n
    return None


def _all_full_and_dr():
    "Return None once r1 is Full with both peers and DR on the LAN."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    states = [n.get("nbrState", "") for n in _r1_neighbors()]
    if len(states) < 2 or not all(s.startswith("Full") for s in states):
        return "not Full with both peers yet: %s" % states
    intf = r1.vtysh_cmd("show ip ospf interface r1-eth0 json", isjson=True)
    if intf.get("interfaces", {}).get("r1-eth0", {}).get("state") != "DR":
        return "r1 is not DR on the LAN yet"
    return None


def _r1_router_id(rid):
    tgen = get_topogen()
    out = tgen.gears["r1"].vtysh_cmd("show ip ospf json", isjson=True)
    if out.get("routerId") == rid:
        return None
    return "router-id is %s, expected %s" % (out.get("routerId"), rid)


def _lan_dr_and_netlsa_valid():
    "Return None once the LAN DR and Network-LSA are valid on r1."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    oi = (
        r1.vtysh_cmd("show ip ospf interface r1-eth0 json", isjson=True)
        .get("interfaces", {})
        .get("r1-eth0", {})
    )
    dr_id = oi.get("drId", "0.0.0.0")
    dr_addr = oi.get("drAddress", "0.0.0.0")
    if dr_id == "0.0.0.0" or dr_addr == "0.0.0.0":
        return "DR not re-elected (drId=%s drAddress=%s)" % (dr_id, dr_addr)
    if dr_addr != DR_ADDR:
        return "interface DR address is %s, expected %s" % (dr_addr, DR_ADDR)

    db = r1.vtysh_cmd("show ip ospf database network json", isjson=True)
    lsids = [
        lsa.get("linkStateId")
        for area in db.get("networkLinkStates", {}).get("areas", {}).values()
        if isinstance(area, list)
        for lsa in area
    ]
    if not lsids:
        return "no Network-LSA present yet"
    if "0.0.0.0" in lsids:
        return "Network-LSA has a zero Link State ID: %s" % lsids
    if DR_ADDR not in lsids:
        return "Network-LSA Link State ID %s not present in %s" % (DR_ADDR, lsids)
    return None


def _p2p_full():
    "Return None once r1's point-to-point neighbor (r3) is Full."
    nbr = _p2p_neighbor()
    if nbr is None:
        return "point-to-point neighbor missing"
    if not nbr.get("nbrState", "").startswith("Full"):
        return "point-to-point neighbor not Full: %s" % nbr.get("nbrState")
    return None


def test_ospf_rid_change_dr():
    "DR re-election on a router-id change must not reset point-to-point links."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("waiting for r1 to be Full with both peers and DR on the LAN")
    _, result = topotest.run_and_expect(_all_full_and_dr, None, count=40, wait=1)
    assert result is None, "initial convergence failed: %s" % result
    assert _lan_dr_and_netlsa_valid() is None, "baseline LAN DR/Network-LSA invalid"
    assert _p2p_full() is None, "point-to-point adjacency not Full at baseline"

    # Trigger a zebra-driven router-id change (a loopback is preferred for
    # the router-id), applied without an interface reset (the buggy path).
    logger.info("adding loopback %s on r1 to force a router-id change", NEW_RID)
    r1.vtysh_cmd(
        "configure terminal\ninterface lo\n ip address %s/32\nend" % NEW_RID
    )

    # Watch the point-to-point neighbor throughout the change. The DR
    # re-election must be scoped to the broadcast interface: a full
    # interface reset would delete this neighbor, so it must never leave
    # r1's neighbor table. The window comfortably spans the router-id
    # change and the broadcast reconvergence.
    rid_changed = False
    for _ in range(50):  # ~10s
        assert _p2p_neighbor() is not None, (
            "point-to-point neighbor was removed: the router-id change reset a "
            "non-DR interface"
        )
        if _r1_router_id(NEW_RID) is None:
            rid_changed = True
        time.sleep(0.2)

    assert rid_changed, "r1 router-id did not change to %s" % NEW_RID

    # The LAN DR must be re-elected and the Network-LSA re-originated.
    _, result = topotest.run_and_expect(
        _lan_dr_and_netlsa_valid, None, count=30, wait=1
    )
    assert result is None, "LAN DR/Network-LSA not valid after change (%s)" % result

    # The point-to-point adjacency re-syncs (the router-id change is a new
    # identity to the peer) but must recover to Full.
    _, result = topotest.run_and_expect(_p2p_full, None, count=30, wait=1)
    assert result is None, "point-to-point adjacency did not recover (%s)" % result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
