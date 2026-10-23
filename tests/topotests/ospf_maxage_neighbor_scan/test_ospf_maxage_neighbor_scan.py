#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_maxage_neighbor_scan.py
#
# Copyright (c) 2026 ATCorp
#

"""
test_ospf_maxage_neighbor_scan.py
=================================

Regression for per-LSA repeated neighbor scans in the RFC 2328 section 13
step (4) path (ospf_ls_upd).

An LSU carrying M unknown MaxAge LSAs used to call
ospf_check_nbr_status() once per LSA.  Each call walks every enabled
interface and every neighbor on it until it finds one in Exchange or
Loading, so with all neighbors Full a single packet cost O(M*N) neighbor
visits.  The predicate cannot change while the packet is being processed,
so the scan must run at most once per packet.

Topology
--------

    r1 (RID 1.1.1.1, DR) ---- s1 ---- r2 (RID 2.2.2.2, injector)
              |
              h1 (scapy host, RID 3.3.3.3, Exchange holder)

Test plan
---------

1. test_adjacency_full
     Baseline: LAN adjacency reaches Full, LSDB normal.

2. test_unknown_maxage_scan_once_per_packet
     gdb-count ospf_check_nbr_status() calls on r1 while r2 injects one
     LSU with 16 unknown MaxAge LSAs (type 5, adv router 99.99.99.99,
     valid Fletcher checksum, age 3600).  Expect one scan per packet, a
     direct LSAck per LSA on the wire, and no LSA installed.

3. test_nonmaxage_and_invalid_controls
     Same-shaped LSUs with age 1 (installed, no scan), the same LSAs back
     with MaxAge (already in LSDB: no scan, flushed by the maxage
     remover), and a broken Fletcher checksum (rejected before the scan).

4. test_exchange_neighbor_maxage_accepted
     h1 drives r1's neighbor 3.3.3.3 into Exchange and holds it there.
     Unknown MaxAge LSAs must then be accepted into the LSDB per RFC 2328
     section 13 step (4) (no ack, no discard), with at most one scan per
     packet.  Once h1 goes silent the neighbor dies and the maxage
     remover flushes them.

The gdb-based call counts are the primary observable; tests 2-4 skip when
gdb or the ospfd symbol is unavailable.
"""

import json
import os
import re
import shlex
import sys
import time
from functools import partial

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

R1_RID = "1.1.1.1"
R2_RID = "2.2.2.2"
H1_RID = "3.3.3.3"
R1_IP = "10.0.0.1"
R2_IP = "10.0.0.2"
H1_IP = "10.0.0.3"
FAKE_ADV = "99.99.99.99"
LSA_ID_PREFIX = "198.18."

GDB_SCRIPT = """set pagination off
set confirm off
handle SIGINT stop print nopass
set $calls = 0
break ospf_check_nbr_status
commands
  silent
  set $calls = $calls + 1
  continue
end
continue
printf "OA1_COUNTS calls=%d\\n", $calls
detach
quit
"""


def lsa_id(index):
    return "198.18.%d.%d" % (index // 256, index % 256)


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    h1 = tgen.add_host("h1", H1_IP + "/24", "via " + R1_IP)
    switch = tgen.add_switch("s1")
    switch.add_link(r1, nodeif="eth1")
    switch.add_link(r2, nodeif="eth1")
    switch.add_link(h1, nodeif="eth1")


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


def _vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def _nbr_state(router, rid):
    try:
        data = _vty_json(router, "show ip ospf neighbor %s detail json" % rid)
    except (json.JSONDecodeError, ValueError):
        return None

    def search(value):
        if isinstance(value, dict):
            if "nbrState" in value:
                return value["nbrState"]
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = search(child)
                if found is not None:
                    return found
        return None

    return search(data)


def _wait_until(func, timeout_s=20, interval_s=0.5):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _external_present(router, ls_id):
    data = _vty_json(router, "show ip ospf database external %s json" % ls_id)
    for lsa in data.get("asExternalLinkStates", []):
        if (
            lsa.get("linkStateId") == ls_id
            and lsa.get("advertisingRouter") == FAKE_ADV
        ):
            return True
    return False


def _maxage_ids(router):
    data = _vty_json(router, "show ip ospf database max-age json")
    return set(data.get("maxAgeLinkStates", {}).keys())


def _mac(router):
    return router.cmd("cat /sys/class/net/eth1/address").strip()


def _gdb_usable(router):
    if not router.cmd("which gdb || true").strip():
        return False
    out = router.cmd(
        "gdb -q -batch -ex 'info address ospf_check_nbr_status' "
        "/usr/lib/frr/ospfd 2>&1 || true"
    )
    return 'Symbol "ospf_check_nbr_status" is a function' in out


def _ospfd_pid(router):
    # pidof is ambiguous: all routers share the pid namespace and run
    # identical ospfd cmdlines.  The pid file lives in the router's own
    # mount namespace and names exactly this router's ospfd.
    return router.cmd("cat /var/run/frr/ospfd.pid").strip().splitlines()[-1]


def _gdb_count_start(router, logdir):
    script = os.path.join(logdir, "oa1_count.gdb")
    log = os.path.join(logdir, "oa1_count.log")
    with open(script, "w") as fp:
        fp.write(GDB_SCRIPT)
    router.cmd("rm -f %s" % shlex.quote(log))
    pid = router.cmd(
        "nohup gdb -q -batch -x %s -p %s > %s 2>&1 </dev/null & echo $!"
        % (shlex.quote(script), _ospfd_pid(router), shlex.quote(log))
    ).strip()
    pid = pid.splitlines()[-1]
    assert pid.isdigit(), "gdb did not start on %s (pid %r)" % (router.name, pid)
    assert _wait_until(
        lambda: os.path.exists(log)
        and "Breakpoint 1 at" in open(log, errors="replace").read()
    ), "gdb breakpoints not ready on %s" % router.name
    return pid, log


def _gdb_count_stop(router, pid, log):
    router.cmd("kill -INT %s >/dev/null 2>&1 || true" % pid)

    def _counts():
        if not os.path.exists(log):
            return None
        match = re.search(
            r"OA1_COUNTS calls=(\d+)", open(log, errors="replace").read()
        )
        return int(match.group(1)) if match else None

    assert _wait_until(lambda: _counts() is not None, timeout_s=15), (
        "gdb did not report counts on %s" % router.name
    )
    # Safety net: never leave the daemon stopped.
    router.cmd("kill -CONT %s 2>/dev/null || true" % _ospfd_pid(router))
    return _counts()


def _inject(r2, count, age, first_index, corrupt=False):
    r2.cmd_raises(
        "python3 %s/inject_lsu.py --iface eth1 --src-mac %s --dst-mac %s "
        "--src-ip %s --dst-ip %s --src-rid %s --count %d --age %d "
        "--first-index %d %s"
        % (
            shlex.quote(CWD),
            _mac(r2),
            _mac(get_topogen().gears["r1"]),
            R2_IP,
            R1_IP,
            R2_RID,
            count,
            age,
            first_index,
            "--corrupt" if corrupt else "",
        )
    )


def _exch(h1, mode, extra=""):
    r1 = get_topogen().gears["r1"]
    h1.cmd_raises(
        "python3 %s/exch_hold.py --iface eth1 --src-mac %s --dst-mac %s "
        "--src-ip %s --dst-ip %s --exch-rid %s --victim-rid %s "
        "--victim-ip %s --mode %s %s"
        % (
            shlex.quote(CWD),
            _mac(h1),
            _mac(r1),
            H1_IP,
            R1_IP,
            H1_RID,
            R1_RID,
            R1_IP,
            mode,
            extra,
        )
    )


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _start_capture(router, pcap_path, bpf="ip proto 89"):
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
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
        assert False, "scapy capture did not become ready on %s (pid %s): %s" % (
            router.name,
            pid,
            err.strip() or "no capture stderr",
        )
    return pid


def _proc_alive(router, pid):
    out = router.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
    try:
        return int(out.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        return False


def _stop_capture(router, pid, pcap_path):
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    assert _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ), "pcap %s missing after stopping capture" % pcap_path
    assert _wait_until(
        lambda: os.path.exists(pcap_path + ".json")
    ), "capture sidecar %s.json missing after stopping capture" % pcap_path


def _parse_capture(pcap_path):
    """Return (injected LSU count, injected LSA count, LSAck header count)."""
    with open(pcap_path + ".json") as fp:
        events = json.load(fp)
    lsu = 0
    lsas = 0
    ack_headers = 0
    for event in events:
        if event["type"] == 4 and event["src"] == R2_IP:
            fake = sum(
                1
                for lsa in event.get("lsas", [])
                if lsa["adv_router"] == FAKE_ADV
            )
            if fake:
                lsu += 1
                lsas += fake
        elif event["type"] == 5 and event["src"] == R1_IP:
            ack_headers += sum(
                1
                for header in event.get("ack_headers", [])
                if header["adv_router"] == FAKE_ADV
            )
    return lsu, lsas, ack_headers


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_full(tgen)


def test_unknown_maxage_scan_once_per_packet():
    """One LSU with M unknown MaxAge LSAs must trigger at most one scan."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _expect_full(tgen)
    if not _gdb_usable(r1):
        pytest.skip("gdb or the ospf_check_nbr_status symbol is unavailable")

    ids = [lsa_id(index) for index in range(1, 17)]
    assert not any(_external_present(r1, ls_id) for ls_id in ids)

    capture = os.path.join(tgen.logdir, "maxage_scan.pcap")
    cap_pid = _start_capture(r2, capture)
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _inject(r2, count=16, age=3600, first_index=1)
        time.sleep(2)
    finally:
        calls = _gdb_count_stop(r1, gdb_pid, gdb_log)
    _stop_capture(r2, cap_pid, capture)

    logger.info("ospf_check_nbr_status calls for one 16-LSA LSU: %d", calls)
    assert calls == 1, (
        "ospf_check_nbr_status() called %d times for a single 16-LSA LSU; "
        "the neighbor-state scan must run at most once per packet" % calls
    )

    lsu, lsas, ack_headers = _parse_capture(capture)
    assert lsu == 1 and lsas == 16, "injected LSU not observed once on the wire"
    assert ack_headers == 16, (
        "expected a direct LSAck header per discarded MaxAge LSA, saw %d"
        % ack_headers
    )
    assert not any(_external_present(r1, ls_id) for ls_id in ids), (
        "unknown MaxAge LSAs must be acknowledged and discarded, not installed"
    )


def test_nonmaxage_and_invalid_controls():
    """Non-MaxAge, already-known and corrupt LSAs must not reach the scan."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _expect_full(tgen)
    if not _gdb_usable(r1):
        pytest.skip("gdb or the ospf_check_nbr_status symbol is unavailable")

    ids = [lsa_id(index) for index in range(101, 109)]
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _inject(r2, count=8, age=1, first_index=101)
        time.sleep(2)
    finally:
        calls = _gdb_count_stop(r1, gdb_pid, gdb_log)
    assert calls == 0, "non-MaxAge LSAs must not trigger the neighbor scan"
    assert all(_external_present(r1, ls_id) for ls_id in ids)

    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _inject(r2, count=8, age=3600, first_index=101)
        time.sleep(2)
    finally:
        calls = _gdb_count_stop(r1, gdb_pid, gdb_log)
    assert calls == 0, "MaxAge update for a known LSA must not trigger the scan"
    flushed = _wait_until(
        lambda: not any(_external_present(r1, ls_id) for ls_id in ids),
        timeout_s=75,
        interval_s=1,
    )
    assert flushed, "known LSAs must be flushed by the maxage remover"

    bad_id = lsa_id(201)
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _inject(r2, count=1, age=3600, first_index=201, corrupt=True)
        time.sleep(2)
    finally:
        calls = _gdb_count_stop(r1, gdb_pid, gdb_log)
    assert calls == 0, "checksum-invalid LSA must be rejected before the scan"
    assert not _external_present(r1, bad_id)


def test_exchange_neighbor_maxage_accepted():
    """With a neighbor in Exchange, MaxAge LSAs are accepted, not discarded."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    h1 = tgen.gears["h1"]
    _expect_full(tgen)
    if not _gdb_usable(r1):
        pytest.skip("gdb or the ospf_check_nbr_status symbol is unavailable")

    _exch(h1, "hello_burst", "--count 6 --interval 0.5")
    assert _wait_until(
        lambda: _nbr_state(r1, H1_RID) is not None, timeout_s=20
    ), "h1 neighbor was not created on r1"
    _wait_until(
        lambda: str(_nbr_state(r1, H1_RID)).startswith(("ExStart", "Exchange")),
        timeout_s=20,
    )
    in_exchange = False
    for attempt in range(3):
        _exch(h1, "dd_handshake", "--dd-seq 0x%x" % (0x0A1B2C3D + attempt * 16))
        if _wait_until(
            lambda: str(_nbr_state(r1, H1_RID)).startswith("Exchange"), timeout_s=8
        ):
            in_exchange = True
            break
    assert in_exchange, "h1 neighbor did not reach Exchange on r1"

    hold_pid = h1.cmd(
        "nohup python3 %s/exch_hold.py --iface eth1 --src-mac %s --dst-mac %s "
        "--src-ip %s --dst-ip %s --exch-rid %s --victim-rid %s "
        "--victim-ip %s --mode hold --duration 120 --interval 2 "
        "</dev/null >/dev/null 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            _mac(h1),
            _mac(r1),
            H1_IP,
            R1_IP,
            H1_RID,
            R1_RID,
            R1_IP,
        )
    ).strip()
    hold_pid = hold_pid.splitlines()[-1]
    assert hold_pid.isdigit(), "exch hold did not start on h1"

    ids = [lsa_id(index) for index in range(301, 309)]
    capture = os.path.join(tgen.logdir, "maxage_exchange.pcap")
    cap_pid = _start_capture(r2, capture)
    gdb_pid, gdb_log = _gdb_count_start(r1, tgen.logdir)
    try:
        _inject(r2, count=8, age=3600, first_index=301)
        time.sleep(2)
    finally:
        calls = _gdb_count_stop(r1, gdb_pid, gdb_log)
    _stop_capture(r2, cap_pid, capture)

    logger.info("ospf_check_nbr_status calls for one 8-LSA LSU (Exchange): %d", calls)
    assert calls == 1, (
        "ospf_check_nbr_status() called %d times for a single 8-LSA LSU; "
        "the neighbor-state scan must run at most once per packet" % calls
    )
    _, _, ack_headers = _parse_capture(capture)
    assert ack_headers == 0, (
        "MaxAge LSAs with an Exchange neighbor present must be accepted, "
        "not acknowledged-and-discarded"
    )
    maxage = _maxage_ids(r1)
    assert all(ls_id in maxage for ls_id in ids), (
        "accepted MaxAge LSAs must sit on the maxage list until the "
        "Exchange neighbor is gone"
    )

    h1.cmd("kill %s >/dev/null 2>&1 || true" % hold_pid)
    assert _wait_until(
        lambda: _nbr_state(r1, H1_RID) is None, timeout_s=25
    ), "h1 neighbor did not time out on r1"
    flushed = _wait_until(
        lambda: not any(_external_present(r1, ls_id) for ls_id in ids),
        timeout_s=75,
        interval_s=1,
    )
    assert flushed, "MaxAge LSAs must be flushed once no neighbor is in Exchange"
    _expect_full(tgen)
