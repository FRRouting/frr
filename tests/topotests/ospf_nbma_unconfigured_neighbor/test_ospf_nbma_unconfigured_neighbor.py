#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_nbma_unconfigured_neighbor.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

r"""
test_ospf_nbma_unconfigured_neighbor.py
=======================================

Regression test for the missing receive-side enforcement of statically
configured OSPF neighbors on NBMA interfaces (B8, NBMA scenario).

On non-broadcast interfaces the ``neighbor A.B.C.D`` configuration is
the operator-defined neighbor set: Hellos are sent only to configured
neighbors, and dynamic discovery is not supposed to happen.
ospf_nbr_get() nevertheless created a neighbor for ANY source address
on these interfaces (leaving nbr->nbr_nbma NULL when the source matched
no configured entry), so an on-link attacker could walk an unconfigured
source straight into the neighbor state machine with plain two-way
Hellos - on the network type where operators believe the neighbor set
is pinned.

The point-to-multipoint non-broadcast variant lives in
test_ospf_p2mp_non_broadcast_unconfigured_neighbor.py.

Topology
--------

    r1 (NBMA receiver, RID 8.8.1.1)
      |
      +-- eth0 --+            +-- eth0 -- r2 (configured peer, RID 8.8.1.2)
      |           \          /
      |            +-- s1 --+
      |            +-- s1 --+
      +-- eth0 -- h1 (unconfigured, 10.248.8.3/24)

Segment 10.248.8.0/24: ``ip ospf network non-broadcast`` on r1/r2,
static ``neighbor`` entries only for each other.

All triggers are injected from the unconfigured host's namespace with
scapy (raw Ethernet/IP frames to 224.0.0.5) and captured on the wire
(pcap under tgen.logdir); receipt is cross-checked through the
per-interface helloIn counter and the ospfd log.

Test plan
---------

1. test_baseline
   Interface network type NBMA, 224.0.0.5 membership, exactly one
   static ``neighbor`` line, configured peer Full in both directions,
   unconfigured and invalid sources absent from the neighbor table.
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
    SCENARIO_NBMA,
    check_baseline,
    inject,
    neighbor_entry,
    observe_absence,
    peer_full,
)

pytestmark = [pytest.mark.ospfd]

SCENARIO = SCENARIO_NBMA


def build_topo(tgen):
    receiver = tgen.add_router(SCENARIO["receiver"])
    peer = tgen.add_router(SCENARIO["peer"])
    host = tgen.add_host(
        SCENARIO["host"],
        SCENARIO["host_ip"] + "/24",
        "via " + SCENARIO["receiver_ip"],
    )
    switch = tgen.add_switch(SCENARIO["switch"])
    tgen.add_link(receiver, switch, ifname1="eth0", ifname2="s1-eth0")
    tgen.add_link(peer, switch, ifname1="eth0", ifname2="s1-eth1")
    tgen.add_link(host, switch, ifname1="eth0", ifname2="s1-eth2")


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
        "nbma_invalid_checksum",
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
        "nbma_dd_unconfigured",
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
        "nbma_legitimate_source",
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
        "nbma_hello_unconfigured",
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
        "unconfigured source %s (router ID %s) entered the NBMA neighbor "
        "table despite the pinned static neighbor list: %s"
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
    assert receiver.cmd("pidof ospfd || true").strip(), "ospfd not running on r1"
    assert peer.cmd("pidof ospfd || true").strip(), "ospfd not running on r2"
    assert peer_full(tgen, SCENARIO)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
