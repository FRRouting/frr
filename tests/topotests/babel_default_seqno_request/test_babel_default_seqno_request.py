#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_default_seqno_request.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_babel_default_seqno_request.py
===================================

Regression for babeld dropping a Seqno Request for the default prefix as a
parse failure.

RFC 8966 s4.6.11 only forbids AE=0 in a Seqno Request ("AE ... MUST NOT be
0"); Plen=0 (a default prefix, zero prefix bytes on the wire) is a legal
encoding.  In the unfixed parser, network_prefix() legitimately returns 0
for AE=1/Plen=0 (zero bytes consumed), but the caller treats it as an
error:

  parse_packet()                       babeld/message.c:942-961 (unfixed)
    rc = network_prefix(message[2], message[3], 0, message + 16, ...);
    if (rc <= 0)
        goto fail;                     // rc == 0 -> "Couldn't parse packet"

so the request never reaches handle_request(): it is neither answered nor
forwarded, and a node that lost its default route cannot recover it with a
Seqno Request (RFC 8966 s3.8.1.2).  babeld itself emits exactly this
encoding (AE=1, Plen=0, no prefix bytes) in send_multihop_request() when
requesting an IPv4 default route.  The regression came from 2178d131b9
(PR #13671), which changed `rc < 0` to `rc <= 0` to reject AE=0.

The fix accepts a zero return from network_prefix() as a successful parse
of a zero-length prefix, while AE=0 stays rejected.

Topology
--------

    a1 (attacker) ---- sw1 ---- r1 ---- sw2 ---- r2 ---- sw3 ---- r3

r3 redistributes a kernel default route (installed on r3 before the
routers start) and loopback 10.99.0.1/32; r1 learns both via r2 with r3's
router-id.  r1-eth0 uses update-interval 600000 ms so that periodic
default-route updates toward a1 cannot be mistaken for request responses;
responses are urgent updates sent immediately.

Test plan
---------

1. test_converge
     Baseline: r1 installs 0.0.0.0/0 and 10.99.0.1/32 via r2.

2. test_default_seqno_request_answered
     Seqno Request (AE=1, Plen=0, router-id X, seqno s, hop=1) from a1:
     r1 holds a finite route and must answer with an Update for
     0.0.0.0/0 on r1-eth0 (unfixed: dropped, no answer).

3. test_normal_prefix_seqno_request_answered
     Same for 10.99.0.1/32: answered in BOTH versions (control that
     injection and the normal seqno-request path work).

4. test_ae0_seqno_request_rejected
     Seqno Request with AE=0 (forbidden by RFC 8966 s4.6.11): no answer
     in BOTH versions (control that the fix does not open AE=0).

5. test_default_seqno_request_forwarded
     Seqno Request (AE=1, Plen=0, X, s+10, hop=3) that r1 cannot satisfy:
     it must be forwarded r1 -> r2 (hop count 2 on r1-eth1) and r2 -> r3,
     r3 bumps its seqno, and r1's 0.0.0.0/0 route shows the new seqno
     (unfixed: dropped at r1, seqno unchanged).
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

P_NORM = "10.99.0.1"
P_DEF = "0.0.0.0"
PLEN_NORM = 32
PLEN_DEF = 0
A1_LL = "fe80::a1"


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

    # r3 originates the default route via a kernel route, picked up by
    # babeld through "redistribute ipv4 kernel"
    tgen.gears["r3"].cmd("ip route replace default dev r3-eth0")

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
                "metric": int(m.group(2)),
                "id": m.group(4),
                "seqno": int(m.group(5)),
                "installed": "installed" in m.group(8),
            }
    return routes


def test_converge():
    "Baseline: r1 installs the default route and the loopback route via r2"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_routes():
        routes = _routes(r1)
        for pfx, plen in ((P_DEF, PLEN_DEF), (P_NORM, PLEN_NORM)):
            key = "{}/{}".format(pfx, plen)
            if key not in routes or not routes[key]["installed"]:
                return "route {} not installed yet".format(key)
            if routes[key]["metric"] >= 65535:
                return "route {} not finite yet".format(key)
        ids = {routes["{}/{}".format(p, pl)]["id"] for p, pl in
               ((P_DEF, PLEN_DEF), (P_NORM, PLEN_NORM))}
        if len(ids) != 1:
            return "prefixes have different router-ids: {}".format(ids)
        return None

    _, result = topotest.run_and_expect(check_routes, None, count=90, wait=1)
    assert result is None, "r1 failed to install 0.0.0.0/0 and 10.99.0.1/32"


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


def _send(tgen, ae, pfx, plen, seqno, router_id, hop, count=1):
    a1 = tgen.gears["a1"]
    cmd = (
        "python3 {cwd}/send_mh_request.py --iface a1-eth0 --src {src} "
        "--ae {ae} --prefix {pfx} --plen {plen} --seqno {seqno} --hop {hop} "
        "--router-id {rid} --count {count}".format(
            cwd=shlex.quote(CWD),
            src=A1_LL,
            ae=ae,
            pfx=pfx,
            plen=plen,
            seqno=seqno,
            hop=hop,
            rid=router_id,
            count=count,
        )
    )
    a1.cmd_raises(cmd)


def _tlvs(pcap_path):
    """Yield (kind, ae, plen, seqno, hop, prefix4) for Seqno Request and
    Update TLVs in a pcap; kind in {mhreq, update}."""
    out = []
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 24:
        return out
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
            if t == 10 and len(tlv) >= 14:
                ae = tlv[0]
                plen = tlv[1]
                seqno = int.from_bytes(tlv[2:4], "big")
                hop = tlv[4]
                pb = (plen + 7) // 8
                pbytes = tlv[14 : 14 + pb]
                prefix4 = ".".join(str(b) for b in pbytes) if pb else "0.0.0.0"
                out.append(("mhreq", ae, plen, seqno, hop, prefix4))
            elif t == 8 and len(tlv) >= 10 and tlv[0] == 1:
                plen = tlv[2]
                seqno = int.from_bytes(tlv[6:8], "big")
                pb = (plen + 7) // 8
                pbytes = tlv[10 : 10 + pb]
                prefix4 = ".".join(str(b) for b in pbytes) if pb else "0.0.0.0"
                out.append(("update", 1, plen, seqno, None, prefix4))
            i += 2 + ln
    return out


def _updates_for(pcap_path, prefix4, plen):
    return [
        t
        for t in _tlvs(pcap_path)
        if t[0] == "update" and t[2] == plen and t[5] == prefix4
    ]


def _forwards_for(pcap_path, prefix4, plen, hop):
    return [
        t
        for t in _tlvs(pcap_path)
        if t[0] == "mhreq" and t[1] == 1 and t[2] == plen and t[4] == hop
        and t[5] == prefix4
    ]


def _route_params(r1, pfx, plen):
    routes = _routes(r1)
    key = "{}/{}".format(pfx, plen)
    assert key in routes and routes[key]["installed"], (
        "route {} not installed: {}".format(key, routes)
    )
    return routes[key]["id"], routes[key]["seqno"]


def test_default_seqno_request_answered():
    "A Seqno Request for the default prefix must be answered with an Update"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_d, s_d = _route_params(r1, P_DEF, PLEN_DEF)

    pcap = os.path.join(tgen.logdir, "default_answer.pcap")
    cap_pid = _start_capture(r1, "r1-eth0", pcap)
    try:
        _send(tgen, 1, P_DEF, PLEN_DEF, s_d, rid_d, hop=1)
        time.sleep(2)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    updates = _updates_for(pcap, P_DEF, PLEN_DEF)
    logger.info("default-prefix updates on r1-eth0: %s", updates)
    assert len(updates) >= 1, (
        "Seqno Request for 0.0.0.0/0 (AE=1, Plen=0) got no Update reply on "
        "r1-eth0; RFC 8966 s4.6.11 only forbids AE=0, so the request must "
        "reach handle_request() and be answered"
    )


def test_normal_prefix_seqno_request_answered():
    "A Seqno Request for a normal prefix is answered (control)"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_n, s_n = _route_params(r1, P_NORM, PLEN_NORM)

    pcap = os.path.join(tgen.logdir, "normal_answer.pcap")
    cap_pid = _start_capture(r1, "r1-eth0", pcap)
    try:
        _send(tgen, 1, P_NORM, PLEN_NORM, s_n, rid_n, hop=1)
        time.sleep(2)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    updates = _updates_for(pcap, P_NORM, PLEN_NORM)
    logger.info("10.99.0.1/32 updates on r1-eth0: %s", updates)
    assert len(updates) >= 1, (
        "control: Seqno Request for 10.99.0.1/32 must be answered in both "
        "versions, got no Update reply on r1-eth0"
    )


def test_ae0_seqno_request_rejected():
    "A Seqno Request with AE=0 stays rejected (control)"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_d, s_d = _route_params(r1, P_DEF, PLEN_DEF)

    pcap = os.path.join(tgen.logdir, "ae0_rejected.pcap")
    cap_pid = _start_capture(r1, "r1-eth0", pcap)
    try:
        _send(tgen, 0, P_DEF, PLEN_DEF, s_d, rid_d, hop=1)
        time.sleep(2)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    updates = _updates_for(pcap, P_DEF, PLEN_DEF)
    logger.info("default-prefix updates on r1-eth0 after AE=0 request: %s", updates)
    assert len(updates) == 0, (
        "control: Seqno Request with AE=0 is forbidden by RFC 8966 s4.6.11 "
        "and must not be answered, got %d updates" % len(updates)
    )


def test_default_seqno_request_forwarded():
    "An unsatisfiable default-prefix Seqno Request must be forwarded"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rid_d, s_d = _route_params(r1, P_DEF, PLEN_DEF)

    pcap = os.path.join(tgen.logdir, "default_forward.pcap")
    cap_pid = _start_capture(r1, "r1-eth1", pcap)
    try:
        _send(tgen, 1, P_DEF, PLEN_DEF, s_d + 10, rid_d, hop=3)
        time.sleep(3)
    finally:
        _stop_capture(r1, cap_pid, pcap)

    forwards = _forwards_for(pcap, P_DEF, PLEN_DEF, hop=2)
    logger.info("forwarded default-prefix MH Requests on r1-eth1: %s", forwards)
    assert len(forwards) >= 1, (
        "Seqno Request for 0.0.0.0/0 (AE=1, Plen=0, seqno %d) must be "
        "forwarded r1 -> r2 with hop count 2, got %d forwards"
        % (s_d + 10, len(forwards))
    )

    # r3 (the originator) must bump its seqno, and the new seqno must
    # propagate back to r1's installed default route.

    def check_seqno():
        routes = _routes(r1)
        key = "{}/{}".format(P_DEF, PLEN_DEF)
        if key not in routes or not routes[key]["installed"]:
            return "default route missing"
        if routes[key]["seqno"] == s_d:
            return "default route seqno still %d" % s_d
        return None

    _, result = topotest.run_and_expect(check_seqno, None, count=30, wait=1)
    assert result is None, (
        "r3 did not bump the default-route seqno after the forwarded "
        "request (still %d): %s" % (s_d, result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
