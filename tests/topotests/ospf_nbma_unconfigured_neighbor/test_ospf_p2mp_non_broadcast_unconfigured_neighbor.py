#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_p2mp_non_broadcast_unconfigured_neighbor.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

r"""
test_ospf_p2mp_non_broadcast_unconfigured_neighbor.py
=====================================================

Regression test for the missing receive-side enforcement of statically
configured OSPF neighbors on point-to-multipoint non-broadcast
interfaces (B8, point-to-multipoint non-broadcast scenario).

Same defect as the NBMA scenario
(test_ospf_nbma_unconfigured_neighbor.py): the static ``neighbor``
configuration was never enforced on the receive side, so an
unconfigured on-link source could walk into the neighbor state machine
with plain two-way Hellos.  On point-to-multipoint non-broadcast
networks every neighbor is adjacent, so the rogue source reached
ExStart before the fix.

Topology
--------

    r3 (P2MP-non-broadcast receiver, RID 8.8.2.1)
      |
      +-- eth0 --+            +-- eth0 -- r4 (configured peer, RID 8.8.2.2)
      |           \          /
      |            +-- s2 --+
      |            +-- s2 --+
      +-- eth0 -- h2 (unconfigured, 10.248.9.3/24)

Segment 10.248.9.0/24: ``ip ospf network point-to-multipoint
non-broadcast`` on r3/r4, static ``neighbor`` entries only for each
other.

All triggers are injected from the unconfigured host's namespace with
scapy (raw Ethernet/IP frames to 224.0.0.5) and captured on the wire
(pcap under tgen.logdir); receipt is cross-checked through the
per-interface helloIn counter and the ospfd log.

Test plan
---------

1. test_baseline
   Interface network type POINTOMULTIPOINT with p2mpNonBroadcast,
   224.0.0.5 membership, exactly one static ``neighbor`` line,
   configured peer Full in both directions, unconfigured and invalid
   sources absent from the neighbor table.
2. test_no_attack_control
   Without injection the Full adjacency stays up.
3. test_invalid_checksum_control
   A Hello with a corrupted OSPF checksum from the invalid source is
   dropped before Hello processing: no neighbor is created and a
   "checksum mismatch" is logged.
4. test_dd_from_unconfigured_control
   A Database Description packet from the unconfigured source never
   creates a neighbor (unknown neighbor drop, RFC 2328 section 10.6
   requires an existing adjacency) and is logged; this holds with and
   without the fix.
5. test_legitimate_source_control
   A two-way Hello carrying the configured peer's own address and
   router ID (injected from the host's namespace) still refreshes the
   established Full neighbor: the fix must only fire on the
   neighbor-creation path, never on configured sources.
6. test_unconfigured_source_rejected
   Three valid two-way Hellos from the unconfigured source must not
   create a neighbor: the rogue router ID never appears in the neighbor
   table, the refusal is logged ("not a configured neighbor"), the
   packets are still counted in helloIn, and the configured peer stays
   Full.  Before the fix the same injection walked the rogue into
   ExStart and the test fails with that signature.
7. test_final_convergence
   The configured adjacency Full and the daemons alive at the end.
"""

import os
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.insert(0, CWD)

from scenarios import (  # pylint: disable=wrong-import-position
    CONTROL_DURATION,
    ROGUE_OBSERVE_SECONDS,
    SCENARIO_P2MP,
    check_baseline,
    inject,
    neighbor_entry,
    observe_absence,
    peer_full,
)

pytestmark = [pytest.mark.ospfd]

SCENARIO = SCENARIO_P2MP


def build_topo(tgen):
    receiver = tgen.add_router(SCENARIO["receiver"])
    peer = tgen.add_router(SCENARIO["peer"])
    host = tgen.add_host(
        SCENARIO["host"],
        SCENARIO["host_ip"] + "/24",
        "via " + SCENARIO["receiver_ip"],
    )
    switch = tgen.add_switch(SCENARIO["switch"])
    tgen.add_link(receiver, switch, ifname1="eth0", ifname2="s2-eth0")
    tgen.add_link(peer, switch, ifname1="eth0", ifname2="s2-eth1")
    tgen.add_link(host, switch, ifname1="eth0", ifname2="s2-eth2")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    host = tgen.gears[SCENARIO["host"]]
    host.cmd("ip link set eth0 up")
    host.cmd("ip address replace %s/24 dev eth0" % SCENARIO["host_ip"])

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_baseline():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    check_baseline(tgen, SCENARIO)


def test_no_attack_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    time.sleep(CONTROL_DURATION)
    assert peer_full(tgen, SCENARIO)


def test_invalid_checksum_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    receiver = tgen.gears[SCENARIO["receiver"]]
    phase = inject(
        tgen,
        CWD,
        SCENARIO,
        "p2mp_invalid_checksum",
        "hello",
        SCENARIO["invalid_ip"],
        SCENARIO["invalid_rid"],
        [SCENARIO["receiver_rid"]],
        corrupt_checksum=True,
    )
    time.sleep(1)
    assert (
        neighbor_entry(receiver, SCENARIO["invalid_rid"], SCENARIO["invalid_ip"])
        is None
    ), "corrupted-Checksum Hello created a neighbor"
    assert "checksum mismatch" in phase["log"]
    assert peer_full(tgen, SCENARIO)


def test_dd_from_unconfigured_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    receiver = tgen.gears[SCENARIO["receiver"]]
    phase = inject(
        tgen,
        CWD,
        SCENARIO,
        "p2mp_dd_unconfigured",
        "dd",
        SCENARIO["host_ip"],
        SCENARIO["host_rid"],
        [],
    )
    time.sleep(1)
    assert (
        neighbor_entry(receiver, SCENARIO["host_rid"], SCENARIO["host_ip"]) is None
    ), "DD from the unconfigured source created a neighbor"
    assert "Unknown Neighbor" in phase["log"]
    assert peer_full(tgen, SCENARIO)


def test_legitimate_source_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    phase = inject(
        tgen,
        CWD,
        SCENARIO,
        "p2mp_legitimate_source",
        "hello",
        SCENARIO["peer_ip"],
        SCENARIO["peer_rid"],
        [SCENARIO["receiver_rid"]],
    )
    assert phase["hello_in_delta"] >= 1
    time.sleep(CONTROL_DURATION)
    assert peer_full(tgen, SCENARIO)


def test_unconfigured_source_rejected():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    phase = inject(
        tgen,
        CWD,
        SCENARIO,
        "p2mp_hello_unconfigured",
        "hello",
        SCENARIO["host_ip"],
        SCENARIO["host_rid"],
        [SCENARIO["receiver_rid"]],
        count=3,
    )
    assert phase["hello_in_delta"] >= 3, (
        "unconfigured-source Hellos captured on the wire but receipt not "
        "verified (hello_in_delta=%d)" % phase["hello_in_delta"]
    )
    seen = observe_absence(
        tgen, SCENARIO, SCENARIO["host_rid"], SCENARIO["host_ip"], ROGUE_OBSERVE_SECONDS
    )
    assert not seen, (
        "unconfigured source %s (router ID %s) entered the "
        "point-to-multipoint non-broadcast neighbor table despite the "
        "pinned static neighbor list: %s"
        % (SCENARIO["host_ip"], SCENARIO["host_rid"], seen)
    )
    assert "not a configured neighbor" in phase["log"], (
        "refusal of the unconfigured source was not logged: %s" % phase["log"][-2000:]
    )
    assert peer_full(tgen, SCENARIO), "configured peer disturbed by the rogue injection"


def test_final_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    receiver = tgen.gears[SCENARIO["receiver"]]
    peer = tgen.gears[SCENARIO["peer"]]
    assert receiver.cmd("pidof ospfd || true").strip(), "ospfd not running on r3"
    assert peer.cmd("pidof ospfd || true").strip(), "ospfd not running on r4"
    assert peer_full(tgen, SCENARIO)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
