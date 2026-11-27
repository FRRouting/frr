#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_vl_parallel_transit.py
# Part of NetDEF Topology Tests
#

"""
test_ospf_vl_parallel_transit.py: virtual-link source check with parallel
numbered transit links and opposite per-end preferences.

ospf_associate_packet_vl() must accept the source address the virtual peer
actually sends from.  That address is the address of the peer's own best
path back to us, which with parallel transit links and opposite preferences
is a different one of the peer's interfaces than the peer_addr our SPF
selected.  A check pinned to peer_addr alone drops the peer's legitimate
Hellos and the virtual link never reaches Full.

Topology:

                   area 0.0.0.1 (transit), two parallel links
      link A (p2p, r1 prefers, cost 10/100)   link B (broadcast, r2 prefers)
   r1 (target) ----------------------------- r2 (peer) ---- h1 (attacker)
      |  10.214.1.1/24        10.214.1.2/24      | 10.214.2.2/24   10.214.4.2
      |  10.214.2.1/24        10.214.2.2/24      | 10.214.4.1/24
      |                                         |
   r1-eth2 10.214.3.1/24                    (area 0.0.0.1 stub link)
      |  area 0.0.0.0
   r3 (observer) 10.214.3.2/24

r1 reaches r2 over link A (its own cost 10 beats 100), so r1 sends virtual
link packets from 10.214.1.1 to peer_addr 10.214.1.2.  r2 reaches r1 over
link B (its own cost 10 beats 100), so r2 sends from 10.214.2.2 to
10.214.2.1.  The legitimate adjacency therefore runs between 10.214.1.1 and
10.214.2.2, neither of which matches the other end's peer_addr.

The test:
  1. proves the legitimate virtual link reaches Full with exactly those
     asymmetric source addresses, and floods LSAs across itself (a probe
     prefix on r2 reaches r3 over the backbone),
  2. removes the real peer virtual link and drives a rogue endpoint from h1
     (source 10.214.4.2, the real peer Router ID): the source is not an
     address of the peer, so no adjacency and no injected LSA may appear,
  3. sends a single Hello spoofing the peer's address on the stub link to
     h1 (10.214.4.1): a stub link is not a transit link the peer can source
     virtual-link packets from, so it must be rejected as well.
"""

import json
import os
import shlex
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from ospf_vl_source_check import test_ospf_vl_source_check as vlsc

pytestmark = [pytest.mark.ospfd]

TARGET_RID = "13.13.13.2"  # r1
PEER_RID = "13.13.13.1"  # r2
OBSERVER_RID = "13.13.13.3"  # r3

LINK_A_R1 = "10.214.1.1"
LINK_A_R2 = "10.214.1.2"
LINK_B_R1 = "10.214.2.1"
LINK_B_R2 = "10.214.2.2"
BACKBONE_R1 = "10.214.3.1"
OBSERVER_IP = "10.214.3.2"
ATTACKER_IP = "10.214.4.2"
PEER_ATTACK_IP = "10.214.4.1"

INJECTED_PREFIX = "10.214.99.0"
INJECTED_PREFIX_LENGTH = INJECTED_PREFIX + "/24"
INJECTED_SEQUENCE = 0x80000001

PROBE_PREFIX = "10.214.0.99/32"
PROBE_HOST = "10.214.0.99"


def build_topo(tgen):
    "Build function"
    for r in ("r1", "r2", "r3"):
        tgen.add_router(r)
    tgen.add_host("h1", ATTACKER_IP + "/24", "via " + PEER_ATTACK_IP)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth2")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth2")
    switch.add_link(tgen.gears["h1"], nodeif="h1-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()
    # `debug ospf event` from the config file only sets conf_debug_ospf_event
    # in this tree; IS_DEBUG_OSPF_EVENT reads term_debug_ospf_event, which
    # only the enable-node command sets.  Enable it at runtime so the VL
    # association decisions are logged.
    for name in ("r1", "r2"):
        tgen.gears[name].vtysh_cmd("debug ospf event")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _transit_ready():
    "None once both transit paths and the backbone have converged."
    if not vlsc.one_full(vlsc.neighbor("r1", PEER_RID, "r1-eth0"), LINK_A_R2):
        return "r1 link-A adjacency not Full"
    if not vlsc.one_full(vlsc.neighbor("r1", PEER_RID, "r1-eth1"), LINK_B_R2):
        return "r1 link-B adjacency not Full"
    if not vlsc.one_full(vlsc.neighbor("r2", TARGET_RID, "r2-eth0"), LINK_A_R1):
        return "r2 link-A adjacency not Full"
    if not vlsc.one_full(vlsc.neighbor("r2", TARGET_RID, "r2-eth1"), LINK_B_R1):
        return "r2 link-B adjacency not Full"
    if not vlsc.one_full(vlsc.neighbor("r1", OBSERVER_RID, "r1-eth2")):
        return "r1 backbone adjacency not Full"
    if not vlsc.one_full(vlsc.neighbor("r3", TARGET_RID, "r3-eth0"), BACKBONE_R1):
        return "r3 backbone adjacency not Full"
    return None


def _parallel_vl_ready():
    "None once the VL is Full over the asymmetric parallel transit links."
    transit = _transit_ready()
    if transit is not None:
        return transit
    target_vlink = vlsc.vlink_snapshot("r1")
    peer_vlink = vlsc.vlink_snapshot("r2")
    if not (target_vlink and peer_vlink):
        return "VLINK missing on r1/r2"
    if not (target_vlink["ifUp"] and peer_vlink["ifUp"]):
        return "VLINK not up"
    if target_vlink["ipAddress"] != LINK_A_R1 or target_vlink["vlinkPeer"] != LINK_A_R2:
        return "r1 VL addressing wrong: {}".format(target_vlink)
    if peer_vlink["ipAddress"] != LINK_B_R2 or peer_vlink["vlinkPeer"] != LINK_B_R1:
        return "r2 VL addressing wrong: {}".format(peer_vlink)
    if not vlsc.one_full(
        vlsc.neighbor("r1", PEER_RID, target_vlink["name"]), LINK_B_R2
    ):
        return "r1 VL neighbor not Full from {}".format(LINK_B_R2)
    if not vlsc.one_full(
        vlsc.neighbor("r2", TARGET_RID, peer_vlink["name"]), LINK_A_R1
    ):
        return "r2 VL neighbor not Full from {}".format(LINK_A_R1)
    return None


def _send_raw(node, iface, src, dst, payload):
    "Send one raw OSPF packet from a node namespace."
    out = (
        get_topogen()
        .gears[node]
        .cmd_raises(
            "python3 {} {} {} {} {}".format(
                os.path.join(vlsc.CWD, "send_ospf.py"),
                iface,
                src,
                dst,
                payload.hex(),
            )
        )
    )
    assert "sent=1" in out, "scapy send failed: {}".format(out)


def test_vl_parallel_transit_full():
    "Legitimate VL reaches Full over parallel transit links with opposite preferences."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _, result = topotest.run_and_expect(_transit_ready, None, count=90, wait=1)
    assert result is None, "transit paths not established: {}".format(result)
    pcap = os.path.join(tgen.logdir, "legitimate_parallel_r1eth1.pcap")
    cap_pid = vlsc._start_capture(
        "r1", "r1-eth1", pcap, "ip proto 89 and src host " + LINK_B_R2
    )
    try:
        # Wait for DR election before creating neighbors; otherwise their
        # displayed source address can retain an earlier symmetric path.
        for router, peer in (("r1", PEER_RID), ("r2", TARGET_RID)):
            tgen.gears[router].vtysh_cmd(
                "configure terminal\nrouter ospf\n"
                "area 0.0.0.1 virtual-link {}\nend".format(peer)
            )
        _, result = topotest.run_and_expect(_parallel_vl_ready, None, count=90, wait=1)
    finally:
        vlsc._stop_capture("r1", cap_pid, pcap)
    received = vlsc._count_ospf_packets(pcap, LINK_B_R2, LINK_B_R1)
    logger.info("parallel legitimate packets at r1: %d", received)
    assert received >= 1, "asymmetric peer source did not reach r1"
    assert result is None, "parallel-transit VL not established: {}".format(result)

    assert vlsc.find_lsa("r1", INJECTED_PREFIX) is None
    assert vlsc.find_lsa("r3", INJECTED_PREFIX) is None

    # Flooding across the asymmetric VL: a new area-0 prefix on r2 must
    # reach r3's RIB through the backbone (i.e. across the virtual link).
    tgen.gears["r2"].cmd_raises("ip addr add {} dev lo".format(PROBE_PREFIX))

    def _probe_routed():
        # `ip route show` prints host routes without the /32 suffix.
        out = tgen.gears["r3"].cmd("ip route show {}".format(PROBE_PREFIX))
        if PROBE_HOST in out:
            return None
        return "probe prefix not yet routed on r3"

    _, result = topotest.run_and_expect(_probe_routed, None, count=30, wait=1)
    assert result is None, "probe prefix not flooded over the VL: {}".format(result)

    assert vlsc._ospfd_alive("r1") and vlsc._ospfd_alive("r2")
    assert vlsc._ospfd_alive("r3")


def test_vl_parallel_transit_attack_rejected():
    "Rogue sources must stay rejected on the parallel-transit topology."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Remove the real peer VL and recreate the target VL, so the attack
    # runs against a neighbor-free virtual link (same as the main suite).
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter ospf\n"
        "no area 0.0.0.1 virtual-link {}\nend".format(TARGET_RID)
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter ospf\n"
        "no area 0.0.0.1 virtual-link {0}\n"
        "area 0.0.0.1 virtual-link {0}\nend".format(PEER_RID)
    )

    def _fresh():
        vl = vlsc.vlink_snapshot("r1")
        if not (
            vl
            and vl["ifUp"]
            and vl["ipAddress"] == LINK_A_R1
            and vl["vlinkPeer"] == LINK_A_R2
        ):
            return "target VL not up correctly: {}".format(vl)
        if vlsc.neighbor("r1", PEER_RID, vl["name"]):
            return "stale VL neighbor still present"
        if not vlsc.one_full(vlsc.neighbor("r1", PEER_RID, "r1-eth0"), LINK_A_R2):
            return "transit adjacency lost"
        return None

    _, result = topotest.run_and_expect(_fresh, None, count=30, wait=1)
    assert result is None, "fresh target-only VL not established: {}".format(result)

    vl = vlsc.vlink_snapshot("r1")
    offset = vlsc.ospfd_log_offset("r1")

    trigger_path = os.path.join(tgen.logdir, "allow_lsa_injection.trigger")
    result_path = os.path.join(tgen.logdir, "rogue_capture.json")
    rogue_pcap = os.path.join(tgen.logdir, "rogue_parallel.pcap")
    for path in (trigger_path, result_path, rogue_pcap):
        if os.path.exists(path):
            os.unlink(path)

    helper_cfg = {
        "iface": "h1-eth0",
        "attacker_ip": ATTACKER_IP,
        "target_ip": LINK_A_R1,
        "target_rid": TARGET_RID,
        "peer_rid": PEER_RID,
        "injected_prefix": INJECTED_PREFIX,
        "injected_sequence": INJECTED_SEQUENCE,
        "trigger_path": trigger_path,
        "duration": 45,
        "pcap_path": rogue_pcap,
        "result_path": result_path,
    }
    r1_pcap = os.path.join(tgen.logdir, "attack_parallel_r1eth0.pcap")
    cap_pid = vlsc._start_capture(
        "r1", "r1-eth0", r1_pcap, "ip proto 89 and src host " + ATTACKER_IP
    )
    rogue_pid = None
    try:
        rogue_out = (
            tgen.gears["h1"]
            .cmd(
                "nohup python3 {} {} </dev/null >{} 2>&1 & echo $!".format(
                    shlex.quote(os.path.join(vlsc.CWD, "rogue_vl.py")),
                    shlex.quote(json.dumps(helper_cfg)),
                    shlex.quote(result_path + ".stdout"),
                )
            )
            .strip()
        )
        rogue_pid = rogue_out.splitlines()[-1] if rogue_out else ""
        assert rogue_pid.isdigit(), "rogue helper did not start: {!r}".format(rogue_out)

        # Watch the VL neighbor table while the rogue drives the state machine.
        started = time.monotonic()
        full_entry = None
        while time.monotonic() - started < 20:
            entries = vlsc.neighbor("r1", PEER_RID, vl["name"])
            if vlsc.one_full(entries, ATTACKER_IP):
                full_entry = entries[0]
                break
            time.sleep(0.25)

        # Release the forged Type-5 LSA and watch the LSDBs.
        with open(trigger_path, "w") as fp:
            fp.write("release one type-5 LSU\n")
        lsa_seen = {"r1": False, "r3": False}
        route_seen = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for node in ("r1", "r3"):
                lsa = vlsc.find_lsa(node, INJECTED_PREFIX)
                if (
                    lsa
                    and lsa.get("advertisingRouter") == PEER_RID
                    and int(lsa.get("lsaSeqNumber", "0x0"), 16) == INJECTED_SEQUENCE
                ):
                    lsa_seen[node] = True
            if INJECTED_PREFIX_LENGTH in tgen.gears["r1"].cmd(
                "ip route show {}".format(INJECTED_PREFIX_LENGTH)
            ):
                route_seen = True
            if all(lsa_seen.values()) and route_seen:
                break
            time.sleep(0.25)
    finally:
        if rogue_pid is not None:
            tgen.gears["h1"].cmd(
                "kill -TERM {} >/dev/null 2>&1 || true".format(rogue_pid)
            )
        vlsc._stop_capture("r1", cap_pid, r1_pcap)

    vlsc._wait_until(lambda: vlsc._file_ready(result_path), timeout_s=10)
    captured = vlsc._count_ospf_packets(r1_pcap, ATTACKER_IP, LINK_A_R1)
    attack_log = vlsc.ospfd_log_since("r1", offset)
    with open(result_path) as fp:
        rogue_result = json.load(fp)

    logger.info(
        "parallel attack evidence: rogue_packets_at_r1=%d full_entry=%s "
        "lsa_seen=%s route_seen=%s dd_complete=%s",
        captured,
        full_entry,
        lsa_seen,
        route_seen,
        rogue_result.get("dd_complete_observed"),
    )

    assert captured >= 1, "rogue packets did not reach r1 (attack did not happen)"
    assert (
        full_entry is None
    ), "wrong-source VL adjacency reached Full from {}: {}".format(
        ATTACKER_IP, full_entry
    )
    assert not any(
        lsa_seen.values()
    ), "forged Type-5 LSA installed (r1={} r3={})".format(
        lsa_seen["r1"], lsa_seen["r3"]
    )
    assert not route_seen, "injected route {} installed on r1".format(
        INJECTED_PREFIX_LENGTH
    )

    # Neither the transit-area stub address nor the peer's backbone
    # loopback can be the source of this transit-area virtual link.
    vl = vlsc.vlink_snapshot("r1")
    assert vl, "target VL absent"
    for source in (PEER_ATTACK_IP, "10.214.0.2"):
        offset = vlsc.ospfd_log_offset("r1")
        # Send directly from the peer: forwarding a packet spoofing r2's
        # own address through r2 would hit Linux's local-source checks.
        _send_raw("r2", "r2-eth0", source, LINK_A_R1, vlsc.make_hello(PEER_RID))
        expected = "packet source {} ".format(source)
        _, result = topotest.run_and_expect(
            lambda: any(
                expected in line and "not associating" in line
                for line in vlsc.ospfd_log_since("r1", offset).splitlines()
            ),
            True,
            count=10,
            wait=1,
        )
        assert result is True, "source {} rejection not logged".format(source)
        assert not vlsc.neighbor(
            "r1", PEER_RID, vl["name"]
        ), "source {} created a VL neighbor".format(source)

    assert vlsc._ospfd_alive("r1") and vlsc._ospfd_alive("r2")
    assert vlsc._ospfd_alive("r3")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
