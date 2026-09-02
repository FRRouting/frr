#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_dd_dup_hang.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
test_ospf_dd_dup_hang.py
========================

Regression for ospfd event-loop starvation when the OSPF Slave retransmits
its last Database Description packet on every duplicate DD from the Master
(RFC 2328 §10.8).  An unbounded Slave resend+zlog_info path can starve
the event loop until the daemon is declared unresponsive.

Topology
--------

    r1 (RID 1.1.1.1, Slave) ----eth1---- r2 (RID 2.2.2.2, Master)

r1 has the lower router-id, so it is the DD Slave.

Test plan
---------

1. test_adjacency_full
     Baseline: point-to-point adjacency reaches Full.

2. test_dd_dup_flood_slave_resend_paced
     Sniff a real DD from the Master (scapy, not tcpdump), replay it
     COUNT times at r1.  r1 must stay responsive (vtysh returns within
     VTYSH_TIMEOUT_S) and must not emit one unicast DD per injected
     duplicate.  Before the pacing fix this burst produced thousands of
     Slave resends.

3. test_p2p_flap_unknown_neighbor_recovers
     Rapidly flap r2's link so packets can arrive before Hello recreates
     the neighbor ("Unknown Neighbor").  r1 must remain responsive and
     the adjacency must return to Full.
"""

import os
import shlex
import sys
import time
from functools import partial

import pytest
from scapy.contrib.ospf import OSPF_Hdr
from scapy.utils import rdpcap

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

FLOOD_COUNT = 3000
# Unfixed ospfd resends ~1:1.  Paced ospfd resends at most once per
# retransmit-interval (5s) during a sub-interval burst.
MAX_SLAVE_DD_TX = 8
VTYSH_TIMEOUT_S = 8
OSPF_MSG_DB_DESC = 2
R1_RID = "1.1.1.1"
R2_RID = "2.2.2.2"


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


def _expect_full(tgen):
    tgen.gears["r1"].expect_ospfv2_neighbor(R2_RID)
    tgen.gears["r2"].expect_ospfv2_neighbor(R1_RID)


def _ospfd_alive(router):
    out = router.cmd("pidof ospfd || true").strip()
    return bool(out)


def _vtysh_responsive(router, timeout_s=VTYSH_TIMEOUT_S):
    """Return (ok, elapsed_s).  timeout(1) yields rc 124 if vtysh blocks."""
    start = time.time()
    rc = router.cmd(
        "timeout %s vtysh -c 'show ip ospf neighbor json' >/dev/null; echo $?"
        % timeout_s
    ).strip()
    elapsed = time.time() - start
    try:
        ok = int(rc.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        ok = False
    return ok, elapsed


def _wait_until(func, timeout_s=5, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _proc_alive(router, pid):
    out = router.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
    try:
        return int(out.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        return False


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _count_dd_from(pcap_path, router_id):
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 24:
        return 0
    n = 0
    for pkt in rdpcap(pcap_path):
        if not pkt.haslayer(OSPF_Hdr):
            continue
        hdr = pkt[OSPF_Hdr]
        if hdr.type == OSPF_MSG_DB_DESC and str(hdr.src) == router_id:
            n += 1
    return n


def _start_capture(router, pcap_path, bpf="ip proto 89"):
    """Sniff with scapy in the router netns. tcpdump is not used: it is often
    missing in CI images and it exits when the peer interface goes down.
    """
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    # nohup: router.cmd() closing the session would otherwise SIGHUP the sniffer.
    pid = router.cmd(
        "nohup python3 %s/capture_ospf.py --iface eth1 --pcap %s "
        "--filter %s --ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
            shlex.quote(ready_path),
            shlex.quote(err_path),
        )
    ).strip()
    if pid:
        pid = pid.splitlines()[-1]
    assert pid.isdigit(), "scapy capture did not start on %s (pid %r)" % (
        router.name,
        pid,
    )
    if not _wait_until(partial(_file_ready, ready_path)):
        err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
        if os.path.exists(err_path):
            with open(err_path) as f:
                err = err or f.read()
        assert False, "scapy capture did not become ready on %s (pid %s): %s" % (
            router.name,
            pid,
            err.strip() or "no capture stderr",
        )
    return pid


def _stop_capture(router, pid, pcap_path):
    err_path = pcap_path + ".err"
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    if not _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ):
        err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
        if os.path.exists(err_path):
            with open(err_path) as f:
                err = err or f.read()
        assert False, "pcap %s missing after stopping capture: %s" % (
            pcap_path,
            err.strip() or "empty/missing file",
        )


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_full(tgen)


def test_dd_dup_flood_slave_resend_paced():
    """Flood duplicate Master DDs at the Slave; ospfd must not wedge or amplify."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _expect_full(tgen)

    # Shared rundir is visible to pytest and to both routers; /tmp in the
    # namespace is not a reliable place to rdpcap from the host.
    capture = os.path.join(tgen.logdir, "exch.pcap")
    cap_pid = _start_capture(r1, capture)
    # Retrigger DD while leaving eth1 up.  Shutdown/no-shutdown takes the
    # p2p peer down and kills in-netns sniffers (tcpdump/tshark/scapy).
    r2.vtysh_cmd("clear ip ospf process")
    _expect_full(tgen)
    _stop_capture(r1, cap_pid, capture)
    n_master_dd = _count_dd_from(capture, R2_RID)
    assert n_master_dd > 0, "capture has no DD packets from master %s" % R2_RID
    logger.info("captured %d master DD packet(s) for replay", n_master_dd)

    txpcap = os.path.join(tgen.logdir, "r1tx.pcap")
    tx_pid = _start_capture(r1, txpcap, "ip proto 89 and src 10.0.0.1")

    flood_cmd = (
        "python3 %s/flood_dd.py --pcap %s --iface eth1 "
        "--src-rid %s --count %d" % (CWD, capture, R2_RID, FLOOD_COUNT)
    )
    logger.info("flooding %d duplicate DDs from r2", FLOOD_COUNT)
    t0 = time.time()
    r2.cmd_raises(flood_cmd)
    flood_s = time.time() - t0
    logger.info("flood finished in %.2fs", flood_s)

    _stop_capture(r1, tx_pid, txpcap)

    assert _ospfd_alive(r1), "ospfd on r1 died during DD duplicate flood"
    ok, elapsed = _vtysh_responsive(r1)
    assert ok, "vtysh on r1 did not return within %ss after DD flood" % VTYSH_TIMEOUT_S
    logger.info("vtysh responded in %.2fs after flood", elapsed)

    slave_dd_tx = _count_dd_from(txpcap, R1_RID)
    logger.info(
        "r1 transmitted %d DD packet(s) during flood of %d duplicates",
        slave_dd_tx,
        FLOOD_COUNT,
    )
    assert slave_dd_tx <= MAX_SLAVE_DD_TX, (
        "Slave DD resend amplification: r1 sent %d DD packets in response to "
        "%d duplicates (limit %d).  RFC 2328 §10.8 requires a resend, not a "
        "1:1 flood." % (slave_dd_tx, FLOOD_COUNT, MAX_SLAVE_DD_TX)
    )

    _expect_full(tgen)


def test_p2p_flap_unknown_neighbor_recovers():
    """Rapid p2p flaps must not wedge ospfd."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _expect_full(tgen)

    for i in range(15):
        r2.link_enable("eth1", enabled=False)
        time.sleep(0.15)
        r2.link_enable("eth1", enabled=True)
        time.sleep(0.15)

    assert _ospfd_alive(r1), "ospfd on r1 died during p2p flaps"
    ok, elapsed = _vtysh_responsive(r1)
    assert ok, "vtysh on r1 hung after p2p flaps (elapsed %.2fs)" % elapsed
    logger.info("vtysh responded in %.2fs after flaps", elapsed)

    _expect_full(tgen)
