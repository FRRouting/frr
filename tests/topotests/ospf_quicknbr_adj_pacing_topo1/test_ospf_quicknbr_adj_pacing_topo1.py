#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Exercise OSPF quick neighbors together with adjacency pacing on a
point-to-point link.

rt1 runs "ip ospf bfd quick" and "ip ospf adjacency-pacing static 1" on its
link to rt2. Its interface MTU is lower than rt2's, so rt1 rejects rt2's
Database Description packets and the adjacency stays in ExStart, holding the
only formation slot.

On point-to-point links neighbors are keyed by router-id, so when BFD comes
up while the OSPF neighbor is still known, a quick neighbor is created under
rt2's address. It reaches TwoWay and waits on the pacing queue behind the
existing adjacency. rt2's next packet tells rt1 the router-id, which already
belongs to the existing neighbor, so the quick neighbor is deleted.

Later uses of the pacing queue (the next quick neighbor queued after a BFD
flap, and the slot release once the MTU mismatch is allowed) must not touch
the deleted quick neighbor: ospfd must keep running and the adjacency must
reach Full.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.ospfd]

BFD_RULES = [
    "INPUT -p udp --dport 3784 -j DROP",
    "OUTPUT -p udp --dport 3784 -j DROP",
]


def setup_module(mod):
    topodef = {"s1": ("rt1:eth-rt2", "rt2:eth-rt1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # rt1 rejects rt2's DD packets until mtu-ignore is configured.
    tgen.gears["rt1"].cmd_raises("ip link set dev eth-rt2 mtu 1400")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def ospf_neighbors(rname):
    router = get_topogen().gears[rname]
    output = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)
    return output.get("neighbors", {})


def ospf_neighbor_state(rname, rid):
    nbrs = ospf_neighbors(rname).get(rid)
    if not nbrs:
        return None
    return nbrs[0].get("nbrState", "").split("/")[0]


def bfd_peer_status(rname, ifname):
    router = get_topogen().gears[rname]
    peers = router.vtysh_cmd("show bfd peers json", isjson=True)
    for peer in peers:
        if peer.get("interface") == ifname:
            return peer.get("status")
    return None


def test_adjacency_held_in_exstart():
    "rt1's adjacency stays in ExStart and its BFD session comes up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for rt1's adjacency to stall in ExStart")
    _, state = topotest.run_and_expect(
        partial(ospf_neighbor_state, "rt1", "2.2.2.2"), "ExStart", count=60, wait=1
    )
    assert state == "ExStart", "rt1: neighbor 2.2.2.2 is {}".format(state)

    step("Wait for rt1's BFD session to come up")
    _, status = topotest.run_and_expect(
        partial(bfd_peer_status, "rt1", "eth-rt2"), "up", count=60, wait=1
    )
    assert status == "up", "rt1: BFD session is {}".format(status)


def test_bfd_up_while_adjacency_in_progress():
    "A BFD flap makes a quick neighbor that queues behind the adjacency."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rt1 = tgen.gears["rt1"]

    step("Drop BFD packets on rt1 until its session goes down")
    for rule in BFD_RULES:
        rt1.cmd_raises("iptables -A " + rule)
    _, status = topotest.run_and_expect(
        partial(bfd_peer_status, "rt1", "eth-rt2"), "down", count=60, wait=1
    )
    assert status == "down", "rt1: BFD session is {}".format(status)

    step("Wait for rt1's adjacency to be back in ExStart")
    _, state = topotest.run_and_expect(
        partial(ospf_neighbor_state, "rt1", "2.2.2.2"), "ExStart", count=60, wait=1
    )
    assert state == "ExStart", "rt1: neighbor 2.2.2.2 is {}".format(state)

    step("Let BFD come back up while the adjacency holds the pacing slot")
    for rule in BFD_RULES:
        rt1.cmd_raises("iptables -D " + rule)
    _, status = topotest.run_and_expect(
        partial(bfd_peer_status, "rt1", "eth-rt2"), "up", count=60, wait=1
    )
    assert status == "up", "rt1: BFD session is {}".format(status)

    step("Wait for the quick neighbor to be replaced by neighbor 2.2.2.2")

    def _only_router_id_neighbor():
        return sorted(ospf_neighbors("rt1").keys())

    _, nbrs = topotest.run_and_expect(
        _only_router_id_neighbor, ["2.2.2.2"], count=60, wait=1
    )
    assert nbrs == ["2.2.2.2"], "rt1: neighbors are {}".format(nbrs)


def test_slot_release_after_quick_neighbor_delete():
    "Releasing the formation slot must not touch the deleted quick neighbor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Allow the MTU mismatch on rt1 so the adjacency can finish")
    tgen.gears["rt1"].vtysh_cmd(
        "configure terminal\ninterface eth-rt2\nip ospf mtu-ignore\nend\n"
    )

    for rname, rid in (("rt1", "2.2.2.2"), ("rt2", "1.1.1.1")):
        _, state = topotest.run_and_expect(
            partial(ospf_neighbor_state, rname, rid), "Full", count=60, wait=1
        )
        assert state == "Full", "{}: neighbor {} is {}".format(rname, rid, state)

    assert not tgen.routers_have_failure(), tgen.errors


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
