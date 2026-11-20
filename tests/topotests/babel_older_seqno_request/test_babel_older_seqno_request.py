#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_older_seqno_request.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_babel_older_seqno_request.py
=================================

Regression for babeld forwarding an OLDER Seqno Request again while a
NEWER request for the same (prefix, router-id) is still pending, and for
that older request refreshing the newer pending entry (extending its
REQUEST_TIMEOUT lifetime and resetting its resend budget).

RFC 8966 s3.8.1.2: a node SHOULD avoid forwarding a seqno request that is
redundant, "i.e., if the node has recently sent a request with the same
prefix, router-id, and a seqno that is not smaller modulo 2^(16)".

Code path (babeld/resend.c, unfixed):

  request_redundant() returned "not redundant" when the recorded seqno
  was GREATER than the incoming one, so handle_request() forwarded the
  older duplicate again; record_resend() then refreshed the pending
  entry's time/max before rejecting the older seqno.

Topology
--------

    a1 (attacker) ---- sw1 ---- r1 ---- sw2 ---- r2 ---- sw3 ---- r3

r3 redistributes three loopback /32s (10.99.0.1, 10.99.1.1, 10.99.2.1).
r1 learns them via r2 with router-id X and seqno s (both read at runtime
from "show babel route").  Injected Seqno Requests (P, X, s+q, hop=2)
are not satisfiable from r1's route (q > 0) and not hopelessly out of
date (q <= 20), so they reach request_redundant().  hop=2 makes r1
forward with hop=1; r2 is a relay, not the originator, and drops the
request at its own hop-count check, so r3's advertised seqno stays
constant for the whole run.

Test plan
---------

1. test_converge
     Baseline: r1 installs the three 10.99.x.1/32 routes via r2.

2. test_older_seqno_request_not_forwarded
     Suppression matrix on 10.99.0.1/32, counted as unicast MH Requests
     forwarded r1 -> r2 on r1-eth1 (scapy capture, aggregate per
     (prefix, seqno)):
       first request (s+10)    -> forwarded once
       same seqno (s+10)       -> suppressed (count stays 1)
       OLDER seqno (s+5)       -> must NOT be forwarded (bug: forwarded)
       newer seqno (s+20)      -> suppressed by the pre-existing
                                  "max > 0" branch (unchanged by the fix)
       different router-id     -> update reply, no forward
       different prefix (s+10) -> forwarded (fresh pending)

3. test_older_seqno_request_not_refresh_pending
     Lifecycle on 10.99.2.1/32 with REQUEST_TIMEOUT = 65000 ms:
       t=0      first request (s+10)  -> forwarded; pending expires t=65
       t=5,6,7  OLDER requests (s+5) -> must NOT be forwarded and must
                                        NOT push the expiry back
       t=67     equal probe (s+10)   -> must be forwarded because the
                                        pending expired at t=65 (bug:
                                        pending refreshed at t=7, probe
                                        suppressed)
"""

import os
import re
import shlex
import sys
import time
from functools import partial

import pytest
from scapy.all import UDP
from scapy.utils import rdpcap

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.babeld]

P_A = "10.99.0.1"
P_ALT = "10.99.1.1"
P_B = "10.99.2.1"
PLEN = 32
FAKE_ID = "00:00:00:00:00:00:00:aa"
A1_LL = "fe80::a1"
REQUEST_TIMEOUT_S = 65


def build_topo(tgen):
    a1 = tgen.add_host("a1", "10.13.0.2/24", "via 10.13.0.1")
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(a1)
    sw1.add_link(r1)

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(r2)

    sw3 = tgen.add_switch("sw3")
    sw3.add_link(r2)
    sw3.add_link(r3)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    a1 = tgen.gears["a1"]
    a1.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=0")
    a1.cmd("sysctl -qw net.ipv6.conf.a1-eth0.disable_ipv6=0")
    a1.cmd("ip -6 addr add {}/64 dev a1-eth0 2>/dev/null || true".format(A1_LL))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


ROUTE_RE = re.compile(
    r"^(\S+) metric (\d+) refmetric (\d+) id ((?:[0-9a-f]{2}:){7}[0-9a-f]{2}) "
    r"seqno (\d+).*via (\S+) neigh (\S+)(.*)$"
)


def _routes(router):
    out = router.vtysh_cmd("show babel route")
    routes = {}
    for ln in out.splitlines():
        m = ROUTE_RE.match(ln.strip())
        if m:
            routes[m.group(1)] = {
                "id": m.group(4),
                "seqno": int(m.group(5)),
                "installed": "installed" in m.group(8),
            }
    return routes


def test_converge():
    "Baseline: r1 installs the three loopback routes via r2"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_routes():
        routes = _routes(r1)
        for pfx in (P_A, P_ALT, P_B):
            key = "{}/{}".format(pfx, PLEN)
            if key not in routes or not routes[key]["installed"]:
                return "route {} not installed yet".format(key)
        ids = {routes["{}/{}".format(p, PLEN)]["id"] for p in (P_A, P_ALT, P_B)}
        if len(ids) != 1:
            return "prefixes have different router-ids: {}".format(ids)
        return None

    _, result = topotest.run_and_expect(check_routes, None, count=90, wait=1)
    assert result is None, "r1 failed to install the 10.99.x.1/32 routes"


def _wait_until(func, timeout_s=5, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _proc_alive(gear, pid):
    out = gear.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
    try:
        return int(out.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        return False


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _start_capture(router, ifname, pcap_path):
    """Sniff with scapy in the router netns.  tcpdump is not used: it is
    often missing in CI images and it exits when the peer interface goes
    down."""
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    # nohup: router.cmd() closing the session would otherwise SIGHUP the sniffer.
    pid = router.cmd(
        "nohup python3 %s/capture_babel.py --iface %s --pcap %s "
        "--ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(ifname),
            shlex.quote(pcap_path),
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
        assert False, "pcap %s missing after stopping capture: %s" % (
            pcap_path,
            err.strip() or "empty/missing file",
        )


def _send(tgen, pfx, seqno, router_id, hop=2, count=1):
    a1 = tgen.gears["a1"]
    cmd = (
        "python3 {cwd}/send_mh_request.py --iface a1-eth0 --src {src} "
        "--prefix {pfx} --plen {plen} --seqno {seqno} --hop {hop} "
        "--router-id {rid} --count {count}".format(
            cwd=shlex.quote(CWD),
            src=A1_LL,
            pfx=pfx,
            plen=PLEN,
            seqno=seqno,
            hop=hop,
            rid=router_id,
            count=count,
        )
    )
    a1.cmd_raises(cmd)


def _mh_forwards(pcap_path):
    """Aggregate forwarded Seqno Requests: {(prefix, seqno, router-id):
    count}.  Only MH Request TLVs with hop count 1 (r1's forwarded copies)
    on the r1-r2 link are counted; injected packets (hop 2) never appear
    there.  Updates and other TLVs are ignored."""
    counts = {}
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 24:
        return counts
    for pkt in rdpcap(pcap_path):
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if udp.dport != 6696 and udp.sport != 6696:
            continue
        payload = bytes(udp.payload)
        if len(payload) < 4 or payload[0] != 42 or payload[1] != 2:
            continue
        body = payload[4:]
        i = 0
        while i + 2 <= len(body):
            t = body[i]
            if t == 0:
                i += 1
                continue
            ln = body[i + 1]
            tlv = body[i + 2 : i + 2 + ln]
            if t == 10 and len(tlv) >= 14 and tlv[0] == 1 and tlv[4] == 1:
                plen = tlv[1]
                seqno = int.from_bytes(tlv[2:4], "big")
                rid = ":".join("{:02x}".format(b) for b in tlv[6:14])
                pb = (plen + 7) // 8
                prefix4 = ".".join(str(b) for b in tlv[14 : 14 + pb])
                key = ("{}/{}".format(prefix4, plen), seqno, rid)
                counts[key] = counts.get(key, 0) + 1
            i += 2 + ln
    return counts


def _route_params(r1, pfx):
    routes = _routes(r1)
    key = "{}/{}".format(pfx, PLEN)
    assert key in routes and routes[key]["installed"], (
        "route {} not installed: {}".format(key, routes)
    )
    return routes[key]["id"], routes[key]["seqno"]


def test_older_seqno_request_not_forwarded():
    "An older duplicate Seqno Request must not be forwarded again"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_a, s_a = _route_params(r1, P_A)
    rid_alt, s_alt = _route_params(r1, P_ALT)
    assert rid_a == rid_alt

    pcap = os.path.join(tgen.logdir, "older_seqno_matrix.pcap")
    cap_pid = _start_capture(r1, "r1-eth1", pcap)
    try:
        _send(tgen, P_A, s_a + 10, rid_a)  # first request: forwarded
        time.sleep(1.5)
        _send(tgen, P_A, s_a + 10, rid_a)  # same seqno: suppressed
        time.sleep(1.5)
        _send(tgen, P_A, s_a + 5, rid_a)  # OLDER: must be suppressed
        time.sleep(1.5)
        _send(tgen, P_A, s_a + 20, rid_a)  # newer: suppressed (max > 0)
        time.sleep(1.5)
        _send(tgen, P_A, s_a + 10, FAKE_ID)  # different router-id: no forward
        time.sleep(1.5)
        _send(tgen, P_ALT, s_alt + 10, rid_alt)  # different prefix: forwarded
        time.sleep(1.5)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    counts = _mh_forwards(pcap)
    logger.info("forwarded MH Requests on r1-eth1: %s", counts)

    key_first = ("{}/{}".format(P_A, PLEN), s_a + 10, rid_a)
    key_older = ("{}/{}".format(P_A, PLEN), s_a + 5, rid_a)
    key_newer = ("{}/{}".format(P_A, PLEN), s_a + 20, rid_a)
    key_alt = ("{}/{}".format(P_ALT, PLEN), s_alt + 10, rid_alt)

    assert counts.get(key_first, 0) == 1, (
        "first request must be forwarded exactly once, got %d" % counts.get(key_first, 0)
    )
    assert counts.get(key_older, 0) == 0, (
        "OLDER duplicate (seqno %d) must not be forwarded while seqno %d is "
        "pending (RFC 8966 s3.8.1.2), got %d forwards"
        % (s_a + 5, s_a + 10, counts.get(key_older, 0))
    )
    assert counts.get(key_newer, 0) == 0, (
        "newer request must stay suppressed by the pending entry, got %d"
        % counts.get(key_newer, 0)
    )
    assert counts.get(key_alt, 0) == 1, (
        "request for a different prefix must be forwarded, got %d"
        % counts.get(key_alt, 0)
    )
    unexpected = {k: v for k, v in counts.items() if k[2] != rid_a}
    assert not unexpected, "unexpected forwards (wrong router-id): %s" % unexpected
    assert sum(counts.values()) == 2, (
        "exactly the first request and the different-prefix request must be "
        "forwarded, got %d: %s" % (sum(counts.values()), counts)
    )


def test_older_seqno_request_not_refresh_pending():
    "An older duplicate must not refresh the newer pending entry"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_b, s_b = _route_params(r1, P_B)

    pcap = os.path.join(tgen.logdir, "older_seqno_lifecycle.pcap")
    cap_pid = _start_capture(r1, "r1-eth1", pcap)
    try:
        t0 = time.time()
        _send(tgen, P_B, s_b + 10, rid_b)  # first request: pending expires t=65
        for t_at in (5, 6, 7):
            delay = t_at - (time.time() - t0)
            if delay > 0:
                time.sleep(delay)
            _send(tgen, P_B, s_b + 5, rid_b)  # OLDER: must not refresh
        probe_at = REQUEST_TIMEOUT_S + 2
        delay = probe_at - (time.time() - t0)
        if delay > 0:
            time.sleep(delay)
        _send(tgen, P_B, s_b + 10, rid_b)  # probe: pending must be gone
        time.sleep(1.5)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    counts = _mh_forwards(pcap)
    logger.info("forwarded MH Requests on r1-eth1: %s", counts)

    key_first = ("{}/{}".format(P_B, PLEN), s_b + 10, rid_b)
    key_older = ("{}/{}".format(P_B, PLEN), s_b + 5, rid_b)

    assert counts.get(key_older, 0) == 0, (
        "OLDER duplicate (seqno %d) must not be forwarded while seqno %d is "
        "pending (RFC 8966 s3.8.1.2), got %d forwards"
        % (s_b + 5, s_b + 10, counts.get(key_older, 0))
    )
    assert counts.get(key_first, 0) == 2, (
        "pending entry must expire REQUEST_TIMEOUT (65s) after the first "
        "request: the probe at t=%ds must be forwarded, got %d forwards for "
        "seqno %d (expected 2: first + probe)"
        % (REQUEST_TIMEOUT_S + 2, counts.get(key_first, 0), s_b + 10)
    )
    assert sum(counts.values()) == 2, (
        "exactly the first request and the probe must be forwarded, got %d: %s"
        % (sum(counts.values()), counts)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
