#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_ase_forward_scan.py
#
# Copyright (c) 2026 ATCorp
#

"""
test_ospf_ase_forward_scan.py
=============================

Regression for per-LSA repeated forwarding-address locality scans in the
OSPFv2 AS-external route calculation (RFC 2328 section 16.4).

Every AS-external-LSA with a non-zero forwarding address makes
ospf_ase_calculate_route() call ospf_ase_forward_address_check(), which
walks the whole oiflist.  A batch of M external LSAs that carry the same
non-local forwarding address therefore re-scans the identical address M
times per ASE calculation pass, and again on every later pass.  The
interface list cannot change while a pass runs, so the verdict must be
cached per address for the duration of the pass.

Topology
--------

    r1 (RID 1.1.1.1, victim) ---- s1 ---- r2 (RID 2.2.2.2, ASBR)
              |                          |
              h1 (scapy injector)         (isolated after baseline)
              |
              s2 (stub, forces SPF passes via link toggle)

Test plan
---------

1. test_adjacency_full
     Baseline: LAN adjacency reaches Full and the ASBR route exists.

2. test_same_fwd_scan_once_per_pass
     r2 is isolated (link down, within the raised dead interval) and h1
     injects 16 AS-external LSAs with distinct LS IDs and the same
     non-local forwarding address.  gdb counts the scan-loop iterations
     on r1 while an r1 link toggle forces ASE passes.  Expect at most
     one interface scan per pass, not one per LSA.

3. test_zero_fwd_and_corrupt_controls
     Same-shaped LSUs with forwarding address 0.0.0.0 (no scan, LSAs
     installed) and with a broken Fletcher checksum (rejected, no scan).

The gdb-based scan counts are the primary observable; tests 2-3 skip when
gdb or the required source lines are unavailable.
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
R1_IP = "10.0.0.1"
R2_IP = "10.0.0.2"
H1_IP = "10.0.0.3"
FWD = "10.99.99.99"
LSA_ID_PREFIX = "198.18."
BATCH = 16

GDB_SCRIPT = """set pagination off
set confirm off
handle SIGINT stop print nopass
set $calls = 0
set $visits = 0
set $pcalls = 0
set $pvisits = 0
break ospf_ase.c:%(call)d
commands
  silent
  set $calls = $calls + 1
  set $pcalls = $pcalls + 1
  continue
end
break ospf_ase.c:%(loop)d
commands
  silent
  set $visits = $visits + 1
  set $pvisits = $pvisits + 1
  continue
end
break ospf_ase_calculate_timer
commands
  silent
  set $pcalls = 0
  set $pvisits = 0
  continue
end
break ospf_ase.c:%(exit)d
commands
  silent
  printf "OA2_PASS calls=%%d visits=%%d\\n", $pcalls, $pvisits
  continue
end
continue
printf "OA2_TOTAL calls=%%d visits=%%d\\n", $calls, $visits
detach
quit
"""


def lsa_id(index):
    return "198.18.%d.%d" % (index // 256, index % 256)


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    h1 = tgen.add_host("h1", H1_IP + "/24", "via " + R1_IP)
    s1 = tgen.add_switch("s1")
    s1.add_link(r1, nodeif="eth1")
    s1.add_link(r2, nodeif="eth1")
    s1.add_link(h1, nodeif="eth1")
    s2 = tgen.add_switch("s2")
    s2.add_link(r1, nodeif="eth2")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def _wait_until(func, timeout_s=20, interval_s=0.5):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _neighbor_full(router, rid):
    try:
        data = _vty_json(router, "show ip ospf neighbor json")
    except (json.JSONDecodeError, ValueError):
        return False
    entries = data.get("neighbors", {}).get(rid, [])
    return bool(entries) and entries[0].get("converged") == "Full"


def _asbr_route_present(router):
    return R2_RID in router.vtysh_cmd("show ip ospf border-routers")


def _external_ids(router):
    data = _vty_json(router, "show ip ospf database external json")
    ids = set()

    def walk(value):
        if isinstance(value, dict):
            if (value.get("linkStateId", "").startswith(LSA_ID_PREFIX)
                    and value.get("advertisingRouter") == R2_RID):
                ids.add(value["linkStateId"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return ids


def _mac(gear):
    return gear.cmd("cat /sys/class/net/eth1/address").strip()


def _source_lines():
    """Locate the breakpoint lines in ospfd/ospf_ase.c at runtime.

    The scan-call site, the scan-loop body and the ASE-pass exit marker are
    found by pattern so the same test works on any tree that contains the
    check, including this fix (which shifts line numbers).
    """
    source = os.path.join(CWD, "..", "..", "..", "ospfd", "ospf_ase.c")
    patterns = {
        "call": r"if \(!ospf_ase_forward_address_check\(ospf,",
        "loop": r"if \(if_is_operative\(oi->ifp\)\)",
        "exit": r"if \(ospf->gr_info\.finishing_restart\) \{",
    }
    lines = {}
    with open(source) as fp:
        content = fp.readlines()
    for key, pattern in patterns.items():
        for lineno, text in enumerate(content, 1):
            if re.search(pattern, text):
                lines[key] = lineno
                break
        else:
            raise LookupError("pattern %r not found in ospf_ase.c" % pattern)
    return lines


def _gdb_usable(router):
    if not router.cmd("which gdb || true").strip():
        return False
    try:
        _source_lines()
    except (OSError, LookupError):
        return False
    return True


def _ospfd_pid(router):
    # pidof is ambiguous: all routers share the pid namespace and run
    # identical ospfd cmdlines.  The pid file lives in the router's own
    # mount namespace and names exactly this router's ospfd.
    return router.cmd("cat /var/run/frr/ospfd.pid").strip().splitlines()[-1]


def _gdb_start(router, logdir):
    script = os.path.join(logdir, "oa2_count.gdb")
    log = os.path.join(logdir, "oa2_count.log")
    with open(script, "w") as fp:
        fp.write(GDB_SCRIPT % _source_lines())
    router.cmd("rm -f %s" % shlex.quote(log))
    pid = router.cmd(
        "nohup gdb -q -batch -x %s -p %s > %s 2>&1 </dev/null & echo $!"
        % (shlex.quote(script), _ospfd_pid(router), shlex.quote(log))
    ).strip()
    pid = pid.splitlines()[-1]
    assert pid.isdigit(), "gdb did not start on %s (pid %r)" % (router.name, pid)
    assert _wait_until(
        lambda: os.path.exists(log)
        and "Breakpoint 4 at" in open(log, errors="replace").read()
    ), "gdb breakpoints not ready on %s" % router.name
    return pid, log


def _gdb_stop(router, pid, log):
    router.cmd("kill -INT %s >/dev/null 2>&1 || true" % pid)

    def _totals():
        if not os.path.exists(log):
            return None
        match = re.search(
            r"OA2_TOTAL calls=(\d+) visits=(\d+)", open(log, errors="replace").read()
        )
        return (int(match.group(1)), int(match.group(2))) if match else None

    def _passes():
        if not os.path.exists(log):
            return []
        return [
            (int(m.group(1)), int(m.group(2)))
            for m in re.finditer(
                r"OA2_PASS calls=(\d+) visits=(\d+)",
                open(log, errors="replace").read(),
            )
        ]

    assert _wait_until(lambda: _totals() is not None, timeout_s=15), (
        "gdb did not report counts on %s" % router.name
    )
    # Safety net: never leave the daemon stopped.
    router.cmd("kill -CONT %s 2>/dev/null || true" % _ospfd_pid(router))
    return _totals(), _passes()


def _inject(h1, r1, r2, count, fwd, first_index, corrupt=False):
    h1.cmd_raises(
        "python3 %s/inject_lsu.py --iface eth1 --src-mac %s --dst-mac %s "
        "--src-ip %s --dst-ip %s --src-rid %s --adv-router %s --fwd %s "
        "--count %d --first-index %d %s"
        % (
            shlex.quote(CWD),
            _mac(r2),
            _mac(r1),
            R2_IP,
            R1_IP,
            R2_RID,
            R2_RID,
            fwd,
            count,
            first_index,
            "--corrupt" if corrupt else "",
        )
    )


def _raise_dead_interval(router, iface, seconds=300):
    router.vtysh_cmd(
        "configure terminal\ninterface %s\nip ospf dead-interval %d\nend"
        % (iface, seconds)
    )


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    assert _wait_until(lambda: _neighbor_full(r1, R2_RID), timeout_s=90), (
        "r1-r2 adjacency did not reach Full"
    )
    assert _wait_until(lambda: _asbr_route_present(r1), timeout_s=30), (
        "r1 has no ASBR route to r2"
    )


def test_same_fwd_scan_once_per_pass():
    """M same-fwd LSAs must cause at most one scan per ASE pass."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    h1 = tgen.gears["h1"]
    assert _wait_until(lambda: _neighbor_full(r1, R2_RID), timeout_s=90)
    assert _wait_until(lambda: _asbr_route_present(r1), timeout_s=30)
    if not _gdb_usable(r1):
        pytest.skip("gdb or the ospf_ase.c source lines are unavailable")

    _raise_dead_interval(r1, "eth1")
    _raise_dead_interval(r2, "eth1")
    # Isolate r2 so it cannot fight back the forged LSAs; r1 keeps the
    # neighbor and the ASBR route inside the dead interval.
    r2.cmd_raises("ip link set dev eth1 down")
    assert _wait_until(lambda: _neighbor_full(r1, R2_RID), timeout_s=10), (
        "r1 lost the r2 neighbor after isolation"
    )
    assert _wait_until(lambda: _asbr_route_present(r1), timeout_s=10), (
        "r1 lost the ASBR route after isolation"
    )

    ids = [lsa_id(index) for index in range(1, BATCH + 1)]
    assert not any(lsa_id in _external_ids(r1) for lsa_id in ids)
    _inject(h1, r1, r2, BATCH, FWD, 1)
    assert _wait_until(
        lambda: all(ls_id in _external_ids(r1) for ls_id in ids), timeout_s=15
    ), "the 16 injected LSAs did not reach the r1 LSDB"

    gdb_pid, gdb_log = _gdb_start(r1, tgen.logdir)
    try:
        # Two link toggles force two SPF runs, hence two ASE passes.
        r1.cmd_raises("ip link set dev eth2 down")
        time.sleep(3)
        r1.cmd_raises("ip link set dev eth2 up")
        time.sleep(3)
    finally:
        (calls, visits), passes = _gdb_stop(r1, gdb_pid, gdb_log)

    logger.info(
        "forward-address check: calls=%d visits=%d passes=%s", calls, visits, passes
    )
    batch_passes = [p for p in passes if p[0] == BATCH]
    assert batch_passes, "no ASE pass processed the injected batch"
    # Each pass must scan the shared forwarding address at most once
    # (2 interfaces before the toggle, 1 while eth2 is down), not once
    # per LSA.
    for pass_calls, pass_visits in batch_passes:
        assert pass_visits <= 2, (
            "ASE pass scanned %d interface entries for %d same-address LSAs; "
            "the forwarding-address verdict must be cached per pass"
            % (pass_visits, pass_calls)
        )
    # All 16 LSAs were still processed exactly once per pass.
    assert calls >= BATCH
    # The LSDB presence (asserted above) plus the per-pass call counts show
    # the target processed every injected LSA; the scan counts are the
    # evidence for the deduplication requirement.
    assert _wait_until(
        lambda: all(ls_id in _external_ids(r1) for ls_id in ids), timeout_s=10
    ), "injected LSAs vanished from the LSDB"


def test_zero_fwd_and_corrupt_controls():
    """Zero forwarding address and corrupt LSAs must not reach the scan."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    h1 = tgen.gears["h1"]
    assert _wait_until(lambda: _neighbor_full(r1, R2_RID), timeout_s=90)
    if not _gdb_usable(r1):
        pytest.skip("gdb or the ospf_ase.c source lines are unavailable")

    zero_ids = [lsa_id(index) for index in range(101, 109)]
    gdb_pid, gdb_log = _gdb_start(r1, tgen.logdir)
    try:
        _inject(h1, r1, r2, 8, "0.0.0.0", 101)
        time.sleep(3)
    finally:
        (calls, visits), _ = _gdb_stop(r1, gdb_pid, gdb_log)
    assert calls == 0 and visits == 0, (
        "zero forwarding address must skip the locality scan (calls=%d visits=%d)"
        % (calls, visits)
    )
    assert all(ls_id in _external_ids(r1) for ls_id in zero_ids), (
        "zero-fwd LSAs must be installed normally"
    )

    bad_id = lsa_id(201)
    gdb_pid, gdb_log = _gdb_start(r1, tgen.logdir)
    try:
        _inject(h1, r1, r2, 1, FWD, 201, corrupt=True)
        time.sleep(3)
    finally:
        (calls, visits), _ = _gdb_stop(r1, gdb_pid, gdb_log)
    assert calls == 0 and visits == 0, (
        "checksum-invalid LSA must be rejected before the scan (calls=%d visits=%d)"
        % (calls, visits)
    )
    assert bad_id not in _external_ids(r1)
