#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_isis_snp_churn.py
#
# Copyright (c) 2026 Bing Shui
#

"""
test_isis_snp_churn.py
======================

Regression for isisd retransmission pacing being defeated by duplicate
SNP requests (ISO/IEC 10589 7.3.15.2).

On a point-to-point circuit an LSP requested by a PSNP stays in the
circuit tx queue, retransmitted every 5 seconds until the neighbor
acknowledges it with a PSNP.  A duplicate PSNP requesting the same LSP
must be absorbed by the already-queued copy: setting SRM on an LSP that
already has SRM set is a no-op.  Before the fix every duplicate request
cancelled the pending 5s retransmission timer and scheduled an immediate
re-send, so the requester could drive the LSP send rate up to the packet
arrival rate; the is_retry reset also kept the extra sends invisible in
the lsp-rxmt counter.

Topology
--------

    r1 (47.0001.0100.0000.0001.00) ----eth1 p2p---- r2 (47.0001.0100.0000.0002.00)

The PSNPs are injected from the r2 netns with a crafted source system
ID; on p2p circuits FRR does not validate the SNP source against the
adjacency.  r2's isisd is frozen with SIGSTOP for the duration of the
duplicate burst so the requested LSP stays unacknowledged (the exact
condition the 5s retransmission timer exists for); the freeze is shorter
than the adjacency hold time.

Test plan
---------

1. test_adjacency_up
     Baseline: p2p adjacency reaches Up and the LSDB goes quiet.

2. test_first_psnp_single_response
     Control: one PSNP requesting r1's LSP with a stale entry produces
     exactly one LSP transmission within a second.  This is the
     protocol-required response and must keep working.

3. test_dup_psnp_absorbed_when_in_flight
     With r2 frozen, eight identical duplicate PSNPs must produce only
     the first LSP transmission; the retransmission pacing then fires
     once at ~5s (lsp-rxmt becomes 1).  After r2 is unfrozen it
     acknowledges the queued LSP and the queue drains.

4. test_fresh_request_after_recovery
     After the queue drained, a new PSNP requesting the same LSP is
     answered again (dedup must not stick).
"""

import json
import os
import shlex
import sys
import time

import pytest
from scapy.all import Dot3, Ether
from scapy.utils import rdpcap

from lib.topogen import Topogen, get_topogen


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.isisd]

R1_SYSID = "010000000001"
R2_SYSID = "010000000002"
# Dotted form as shown by vtysh ("show isis neighbor").
R1_SYSID_DOTTED = "0100.0000.0001"
R2_SYSID_DOTTED = "0100.0000.0002"
# Any value the p2p receiver does not associate with the real peer; on
# p2p circuits process_snp() only requires an up p2p adjacency.
UNKNOWN_SYSID = "010000000099"
R1_LSP_ID = R1_SYSID + "0000"
BURST_COUNT = 8
BURST_SPACING = 0.2
# The FRR LSP retransmission timer on p2p circuits is 5 seconds.
RETRY_MS = 5000
RETRY_TOLERANCE_MS = 1500


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _summary(r1):
    out = r1.vtysh_cmd("show isis summary json")
    data = json.loads(out)
    areas = data["vrfs"][0]["areas"]
    tx = areas[0]["tx-pdu-type"]
    return {
        "tx_l2_lsp": tx.get("l2-lsp", 0),
        "lsp_rxmt": tx.get("lsp-rxmt", 0),
        "rx_l2_psnp": areas[0]["rx-pdu-type"].get("l2-psnp", 0),
    }


def _delta(before, after):
    return {k: after[k] - before[k] for k in before}


def _neighbor_up(router, peer_sysid):
    out = router.vtysh_cmd("show isis neighbor")
    return "Up" in out and peer_sysid in out


def _wait_lsdb_quiet(r1, quiet_s=8.0, timeout_s=150.0):
    """Wait until r1's LSP transmission counter is stable for quiet_s."""
    last = _summary(r1)["tx_l2_lsp"]
    stable_since = time.time()
    deadline = stable_since + timeout_s
    while time.time() < deadline:
        time.sleep(2)
        cur = _summary(r1)["tx_l2_lsp"]
        if cur != last:
            last = cur
            stable_since = time.time()
            continue
        if time.time() - stable_since >= quiet_s:
            return True
    return False


def _mac(router):
    return router.cmd("cat /sys/class/net/eth1/address").strip()


def _inject(r2, r2_mac, count, spacing, sent_log):
    cmd = (
        "python3 %s/inject_isis_snp.py --iface eth1 --src-mac %s "
        "--sysid %s --lsp-id %s --seqno 0 --lifetime 100 "
        "--count %d --spacing %s --sent-log %s"
        % (
            shlex.quote(CWD),
            shlex.quote(r2_mac),
            UNKNOWN_SYSID,
            R1_LSP_ID,
            count,
            spacing,
            shlex.quote(sent_log),
        )
    )
    r2.cmd_raises(cmd)
    with open(sent_log) as fp:
        return json.load(fp)


def _lsp_frames(pcap_path, src_mac):
    """Return (time, seqno) of L2 LSP frames sent by src_mac."""
    frames = []
    for pkt in rdpcap(pcap_path):
        if pkt.haslayer(Ether):
            src, raw = pkt[Ether].src, bytes(pkt[Ether].payload)
        elif pkt.haslayer(Dot3):
            src, raw = pkt[Dot3].src, bytes(pkt[Dot3].payload)
        else:
            continue
        if len(raw) < 24 or raw[0] != 0xFE or raw[1] != 0xFE or raw[2] != 0x03:
            continue
        pdu = raw[3:]
        if pdu[0] != 0x83 or (pdu[4] & 0x1F) != 20 or src != src_mac:
            continue
        seqno = int.from_bytes(pdu[20:24], "big")
        frames.append((float(pkt.time), seqno))
    frames.sort()
    return frames


def _start_capture(r1, pcap_path):
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    r1.cmd("rm -f %s %s %s" % (pcap_path, err_path, ready_path))
    pid = r1.cmd(
        "nohup python3 %s/capture_isis.py --iface eth1 --pcap %s "
        "--ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (CWD, pcap_path, ready_path, err_path)
    ).strip()
    if pid:
        pid = pid.splitlines()[-1]
    assert pid.isdigit(), "scapy capture did not start on r1 (pid %r)" % pid
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(ready_path):
        time.sleep(0.1)
    assert os.path.exists(ready_path), "scapy capture not ready on r1"
    return pid


def _stop_capture(r1, pid, pcap_path):
    r1.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    deadline = time.time() + 8
    while time.time() < deadline:
        alive = r1.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
        if alive.splitlines()[-1] != "0":
            break
        time.sleep(0.2)
    deadline = time.time() + 8
    while time.time() < deadline and not os.path.exists(pcap_path):
        time.sleep(0.2)
    assert os.path.exists(pcap_path), "pcap %s missing after capture" % pcap_path


def _isisd_pid(router):
    return int(router.cmd("cat /var/run/frr/isisd.pid").strip())


def test_adjacency_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    deadline = time.time() + 90
    while time.time() < deadline:
        if _neighbor_up(r1, R2_SYSID_DOTTED) and _neighbor_up(r2, R1_SYSID_DOTTED):
            break
        time.sleep(1)
    assert _neighbor_up(r1, R2_SYSID_DOTTED), "r1 has no Up p2p adjacency to r2"
    assert _neighbor_up(r2, R1_SYSID_DOTTED), "r2 has no Up p2p adjacency to r1"
    assert _wait_lsdb_quiet(r1), "r1 LSDB did not go quiet after adjacency up"


def test_first_psnp_single_response():
    """One PSNP requesting an LSP must produce exactly one LSP send."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    assert _wait_lsdb_quiet(r1)

    sent_log = os.path.join(tgen.logdir, "first_psnp_sent.json")
    pcap = os.path.join(tgen.logdir, "first_psnp.pcap")
    before = _summary(r1)
    cap_pid = _start_capture(r1, pcap)
    inject = _inject(r2, _mac(r2), 1, 0, sent_log)
    time.sleep(1.5)
    after = _summary(r1)
    _stop_capture(r1, cap_pid, pcap)

    delta = _delta(before, after)
    assert delta["rx_l2_psnp"] >= 1, "r1 did not receive the injected PSNP"
    assert delta["tx_l2_lsp"] == 1, (
        "single PSNP must produce exactly one LSP send, got %d"
        % delta["tx_l2_lsp"]
    )
    assert delta["lsp_rxmt"] == 0

    frames = _lsp_frames(pcap, _mac(r1))
    assert len(frames) == 1, "expected one L2 LSP frame on the wire, got %d" % len(
        frames
    )
    latency = frames[0][0] - inject["epoch"] - inject["sent"][0]
    assert latency < 1.0, "LSP response latency %.3fs exceeds 1s" % latency


def test_dup_psnp_absorbed_when_in_flight():
    """Duplicate PSNPs must not cancel the pending 5s retransmission."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    assert _wait_lsdb_quiet(r1, quiet_s=10.0, timeout_s=90.0)

    r2_mac = _mac(r2)
    r1_mac = _mac(r1)
    sent_log = os.path.join(tgen.logdir, "dup_psnp_sent.json")
    pcap = os.path.join(tgen.logdir, "dup_psnp.pcap")
    r2_pid = _isisd_pid(r2)
    r2.cmd("kill -STOP %d" % r2_pid)
    try:
        before = _summary(r1)
        cap_pid = _start_capture(r1, pcap)
        _inject(r2, r2_mac, BURST_COUNT, BURST_SPACING, sent_log)
        time.sleep(1.0)
        after_burst = _summary(r1)

        delta_burst = _delta(before, after_burst)
        # The fix: only the first request schedules a send; the seven
        # duplicates are absorbed by the already-queued copy.
        assert delta_burst["tx_l2_lsp"] == 1, (
            "duplicate PSNPs must be absorbed by the in-flight LSP: "
            "%d LSP sends for %d identical requests"
            % (delta_burst["tx_l2_lsp"], BURST_COUNT)
        )
        assert delta_burst["lsp_rxmt"] == 0

        # The queued copy is still retransmitted on the 5s pacing.
        time.sleep(6.0)
        after_retry = _summary(r1)
        delta_retry = _delta(after_burst, after_retry)
        assert delta_retry["tx_l2_lsp"] == 1, (
            "the queued LSP must be retransmitted once on the 5s pacing"
        )
        assert delta_retry["lsp_rxmt"] == 1, (
            "the paced retransmission must be counted in lsp-rxmt"
        )
        _stop_capture(r1, cap_pid, pcap)
    finally:
        r2.cmd("kill -CONT %d" % r2_pid)

    frames = _lsp_frames(pcap, r1_mac)
    assert len(frames) == 2, (
        "wire must show the immediate send plus one paced retry, got %d"
        % len(frames)
    )
    interval_ms = (frames[1][0] - frames[0][0]) * 1000
    assert abs(interval_ms - RETRY_MS) <= RETRY_TOLERANCE_MS, (
        "retry interval %.0fms deviates from %dms pacing"
        % (interval_ms, RETRY_MS)
    )

    # r2 acknowledges the queued LSP after being unfrozen; the queue
    # drains and the adjacency stays up.
    time.sleep(2)
    after_ack = _summary(r1)
    assert after_ack["tx_l2_lsp"] == after_retry["tx_l2_lsp"], (
        "LSP sends continued after the peer acknowledged the LSP"
    )
    assert _neighbor_up(r1, R2_SYSID_DOTTED), "p2p adjacency did not survive the freeze"


def test_fresh_request_after_recovery():
    """A new PSNP after the queue drained must be answered again."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    assert _wait_lsdb_quiet(r1, quiet_s=10.0, timeout_s=90.0)

    sent_log = os.path.join(tgen.logdir, "fresh_psnp_sent.json")
    before = _summary(r1)
    _inject(r2, _mac(r2), 1, 0, sent_log)
    time.sleep(1.5)
    after = _summary(r1)

    delta = _delta(before, after)
    assert delta["tx_l2_lsp"] == 1, (
        "a fresh PSNP after recovery must be answered, got %d sends"
        % delta["tx_l2_lsp"]
    )
