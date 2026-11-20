#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# test_babel_infinite_seqno_request.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_infinite_seqno_request.py: a Seqno Request must not be
"satisfied" by an installed route whose metric is INFINITY.

RFC 8966 section 3.8.1.2 only allows a *finite-metric* selected route to
answer a seqno request directly ("If a selected route for the given
prefix exists and has finite metric, and either the router-ids are
different or the router-ids are equal and the entry's sequence number is
no smaller ... than the requested sequence number, the node MUST send an
update for the given prefix.").  An INFINITY-metric installed route is a
retraction: it cannot satisfy the request.  Unpatched, handle_request()
in babeld/message.c answers anyway (send_update() with metric INFINITY)
and returns, skipping the hop-count and forwarding logic, so the request
dies at this node instead of being forwarded towards the source or
another successor.

Topology:

    sw1: r1-eth0 (fe80::1)  -- r2-eth0 (fe80::2, originates P)
    sw2: r1-eth1 (fe80::11) -- r3-eth0 (fe80::3) -- h1-eth0 (fe80::a1)

The request is injected on sw2 while the route was learned on sw1,
because with split horizon (default on wired interfaces) an update for a
route is not sent back on the interface the route was learned from.

State construction (verified over vtysh, mirrors the runtime repro):
  A (installed via r2) starts finite.  r3 originates only a canary
  prefix; h1 sniffs r3's seqno H3 for it.  h1 then forges an update for
  P from r3's address with seqno H3+100, creating source (R3,P) and a
  feasible route B via r3.  Only afterwards is P added to r3's loopback,
  so r3's genuine advertisement (seqno H3) is unfeasible at r1 and B
  becomes a finite-metric *unfeasible* route (the source table seqno
  stays H3+100 for SOURCE_GC_TIME).  Finally an outbound distribute-list
  denying P is applied on r2, which makes r2 send a real retraction, so
  A becomes metric INFINITY while staying installed (B is unfeasible, so
  route_changed keeps A).

Checks:
  C1  finite-route control: the request is answered with a finite-metric
      update (must keep working)
  C2  no-trigger window: no request, no answer, no forward
  T1  request matching the INFINITY installed route: no INFINITY update
      answer; the request is forwarded to r3 (unicast, hop count 15)
  T2  same with hop count 1: no answer and no forward (hop count
      exhausted)
  T3  same with router-id R3: no answer, forwarded
  Wire evidence on r1-eth1 corroborates the debug-log path evidence.
"""

import os
import re
import shlex
import sys
import time

import pytest

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from scapy.all import IPv6, UDP, rdpcap

from babel_sniff import decode_babel
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

P_PREFIX = "10.98.0.1"
P_PLEN = P_PREFIX + "/32"
C_PREFIX = "10.98.1.1"
R2_LL = "fe80::2"
R3_LL = "fe80::3"
A1_LL = "fe80::a1"
R1_LL = "fe80::11"  # r1-eth1, where the requests arrive
FORGED_METRIC = 128  # > r2's advertised 0, so A stays installed
SEQNO_BUMP = 100  # forged seqno = H3 + bump, keeps src_R3 newer than r3's real seqno
SETTLE_S = 16  # r1's own post-retraction request retransmits (max 3, ~14s)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_host("h1", "10.13.13.2/24", "via 10.13.13.1")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])
    sw2.add_link(tgen.gears["r3"])
    sw2.add_link(tgen.gears["h1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname in ["r1", "r2", "r3"]:
        router = tgen.gears[rname]
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()

    h1 = tgen.gears["h1"]
    h1.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=0")
    h1.cmd("sysctl -qw net.ipv6.conf.h1-eth0.disable_ipv6=0")
    h1.cmd("ip -6 addr add {}/64 dev h1-eth0 2>/dev/null || true".format(A1_LL))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------- vty helpers ----------------


def babel_routes(router):
    "Parse 'show babel route' into a list of dicts."
    out = router.vtysh_cmd("show babel route")
    routes = []
    for ln in out.splitlines():
        m = re.match(
            r"^(\S+) metric (\d+) refmetric (\d+) id (\S+) seqno (\d+) "
            r".*via (\S+) neigh (\S+)(.*)$",
            ln.strip(),
        )
        if not m:
            continue
        suffix = m.group(8)
        routes.append(
            {
                "prefix": m.group(1),
                "metric": int(m.group(2)),
                "refmetric": int(m.group(3)),
                "id": m.group(4),
                "seqno": int(m.group(5)),
                "via": m.group(6),
                "neigh": m.group(7),
                "installed": "(installed)" in suffix,
                "feasible": "(feasible)" in suffix,
                "raw": ln.strip(),
            }
        )
    return routes


def babel_id(router):
    out = router.vtysh_cmd("show babel parameters")
    m = re.search(r"^id\s+=\s+(\S+)", out, re.M)
    assert m, "no babel router id on {}".format(router.name)
    return m.group(1).strip()


def wait_route(router, pred, count=90):
    "Poll 'show babel route' until pred(route) holds; return the route."
    found = []

    def check():
        found.extend(babel_routes(router))
        for rt in found:
            if pred(rt):
                return None
        return "no matching route yet"

    _, result = topotest.run_and_expect(check, None, count=count, wait=1)
    assert result is None, "timed out waiting for route on {}: {}".format(
        router.name, [rt["raw"] for rt in found]
    )
    for rt in found:
        if pred(rt):
            return rt
    raise AssertionError("unreachable")


def route_is_A_finite(rt):
    return (
        rt["prefix"] == P_PLEN
        and rt["installed"]
        and rt["neigh"] == R2_LL
        and rt["metric"] < 65535
    )


def route_is_A_infinity(rt):
    return (
        rt["prefix"] == P_PLEN
        and rt["installed"]
        and rt["neigh"] == R2_LL
        and rt["metric"] >= 65535
    )


def route_is_B_unfeasible(rt):
    return (
        rt["prefix"] == P_PLEN
        and rt["neigh"] == R3_LL
        and not rt["installed"]
        and not rt["feasible"]
        and rt["metric"] < 65535
    )


# ---------------- packet injection and capture ----------------


def send_req(h1, seqno, hop, ridhex, prefix, count=1):
    cmd = "python3 {}/babel_send.py req {} h1-eth0 {} {} {} {} {}".format(
        CWD, A1_LL, seqno, hop, ridhex, prefix, count
    )
    return h1.cmd_raises(cmd)


def forge_r3(h1, seqno, metric, prefix, nh, ridhex):
    cmd = "python3 {}/babel_send.py r3-forge {} h1-eth0 {} {} {} {} {}".format(
        CWD, R3_LL, seqno, metric, prefix, nh, ridhex
    )
    return h1.cmd_raises(cmd)


def learn_canary(h1, prefix, src, timeout=30):
    cmd = "python3 {}/babel_sniff.py --mode canary --iface h1-eth0 --prefix {} --src {} --timeout {}".format(
        CWD, prefix, src, timeout
    )
    out = h1.cmd_raises(cmd)
    m = re.search(r"'seqno': (\d+)", out)
    assert m, "could not learn r3 seqno from canary prefix: {}".format(out)
    return int(m.group(1))


def start_record(node, iface, pcap_path):
    "Start a scapy recorder inside the node netns; returns the pid."
    ready = pcap_path + ".ready"
    node.cmd("rm -f {} {}".format(shlex.quote(pcap_path), shlex.quote(ready)))
    pid = node.cmd(
        "nohup python3 {}/babel_sniff.py --mode record --iface {} --pcap {} --ready-file {} "
        "</dev/null >/dev/null 2>&1 & echo $!".format(
            CWD, iface, shlex.quote(pcap_path), shlex.quote(ready)
        )
    ).strip()
    pid = pid.splitlines()[-1]
    assert pid.isdigit(), "recorder did not start on {} (pid {!r})".format(
        node.name, pid
    )
    t0 = time.time()
    while time.time() - t0 < 10:
        if os.path.exists(ready):
            return pid
        time.sleep(0.2)
    raise AssertionError("recorder did not become ready on {}".format(node.name))


def stop_record(node, pid):
    node.cmd("kill -TERM {} >/dev/null 2>&1 || true".format(pid))
    t0 = time.time()
    while time.time() - t0 < 8:
        alive = node.cmd(
            "kill -0 {} 2>/dev/null && echo yes || echo no".format(pid)
        ).strip()
        if alive != "yes":
            return
        time.sleep(0.3)
    node.cmd("kill -KILL {} >/dev/null 2>&1 || true".format(pid))


# ---------------- pcap parsing ----------------


def parse_pcap(pcap_path):
    "Return timestamped Babel records, preserving each packet's TLV context."
    records = []
    for packet in rdpcap(pcap_path):
        if IPv6 not in packet or UDP not in packet:
            continue
        for record in decode_babel(bytes(packet[UDP].payload)):
            record.update(
                time=float(packet.time), src=packet[IPv6].src, dst=packet[IPv6].dst
            )
            records.append(record)
    return records


def wire_evidence(records, probe):
    "Classify request-correlated wire evidence in window [t0, t1]."
    out = {
        "injected_request": 0,
        "r1_infinity_answer": 0,
        "r1_finite_update_P": 0,
        "r1_forward_hop15": 0,
        "r1_other_unicast_request": 0,
        "r3_update_P": 0,
    }
    requests = [
        record
        for record in records
        if probe["t0"] - 0.2 <= record["time"] <= probe["t1"]
        and record["kind"] == "mhreq"
        and record["src"] == A1_LL
        and record["dst"] == "ff02::1:6"
        and record["prefix"] == P_PLEN
        and record["router_id"] == probe["rid"]
        and record["seqno"] == probe["seqno"]
        and record["hop"] == probe["hop"]
    ]
    out["injected_request"] = len(requests)
    for record in records:
        if not (probe["t0"] - 0.2 <= record["time"] <= probe["t1"]):
            continue
        if record["kind"] == "update" and record.get("prefix") == P_PLEN:
            metric = record["metric"]
            if record["src"] == R1_LL and metric >= 65535:
                out["r1_infinity_answer"] += 1
            elif record["src"] == R1_LL:
                out["r1_finite_update_P"] += 1
            elif record["src"] == R3_LL:
                out["r3_update_P"] += 1
        elif (
            record["kind"] == "mhreq"
            and record["src"] == R1_LL
            and record["dst"] == R3_LL
        ):
            if (
                requests
                and record["time"] >= requests[0]["time"]
                and record["prefix"] == P_PLEN
                and record["router_id"] == probe["rid"]
                and record["seqno"] == probe["seqno"]
                and record["hop"] == 15
            ):
                out["r1_forward_hop15"] += 1
            elif record["hop"] == 127:
                out["r1_other_unicast_request"] += 1
    return out


# ---------------- debug log helpers ----------------
#
# The daemon is started by topotest with "--log file:babeld.log
# --log-level debug", and r1's config enables "debug babel common", so
# the path evidence lands in <logdir>/r1/babeld.log.

ANSWER_NEEDLE = "Sending update to r1-eth1 for 10.98.0.1/32."
FORWARD_NEEDLE = " multi-hop request to fe80::3 for 10.98.0.1/32 (15 hops)"


def _r1_log_path():
    return os.path.join(get_topogen().logdir, "r1", "babeld.log")


def log_len(_r1):
    try:
        return os.path.getsize(_r1_log_path())
    except OSError:
        return 0


def log_count(_r1, off, needle):
    try:
        with open(_r1_log_path(), "rb") as fp:
            fp.seek(off)
            return fp.read().count(needle.encode())
    except OSError:
        return 0


# ---------------- probes ----------------


def request_probe(r1, h1, ridhex, seqno, hop, label):
    "Send one MH Seqno Request; return log offsets and window."
    off0 = log_len(r1)
    t0 = time.time()
    logger.info("%s: seqno=%d hop=%d rid=%s", label, seqno, hop, ridhex)
    send_req(h1, seqno, hop, ridhex, P_PREFIX)
    time.sleep(3)
    t1 = time.time()
    return {
        "off0": off0,
        "t0": t0,
        "t1": t1,
        "label": label,
        "rid": ridhex,
        "seqno": seqno,
        "hop": hop,
    }


# ---------------- tests ----------------

state = {}


def test_converge():
    "Route A is installed via r2 with a finite metric; canary via r3."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    rtA = wait_route(r1, route_is_A_finite)
    state["seqnoA"] = rtA["seqno"]
    state["rid2"] = babel_id(tgen.gears["r2"]).replace(":", "")
    state["rid3"] = babel_id(tgen.gears["r3"]).replace(":", "")
    wait_route(
        r1,
        lambda rt: rt["prefix"] == C_PREFIX + "/32"
        and rt["installed"]
        and rt["neigh"] == R3_LL,
    )
    logger.info("converged: route A %s", rtA["raw"])


def test_c1_finite_control():
    "A finite installed route must still answer the request directly."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    # the startup transient (initial cost INFINITY and the self-request
    # retransmit chain it triggers) must settle before the probe windows
    time.sleep(25)
    pcap = os.path.join(tgen.logdir, "bb6_r1eth1.pcap")
    state["pcap"] = pcap
    state["rec_pid"] = start_record(r1, "r1-eth1", pcap)

    win = request_probe(r1, h1, state["rid2"], state["seqnoA"], 16, "C1 finite control")
    answers = log_count(r1, win["off0"], ANSWER_NEEDLE)
    state["C1"] = win
    assert answers >= 1, "finite route did not answer the request (C1)"


def test_setup_unfeasible_route():
    "Create a finite-metric unfeasible route B via r3 (seqno games)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    h1 = tgen.gears["h1"]

    h3 = learn_canary(h1, C_PREFIX, R3_LL)
    logger.info("r3 real seqno H3=%d", h3)
    forged = (h3 + SEQNO_BUMP) & 0xFFFF
    forge_r3(h1, forged, FORGED_METRIC, P_PREFIX, "10.13.13.3", state["rid3"])
    wait_route(
        r1,
        lambda rt: rt["prefix"] == P_PLEN
        and rt["neigh"] == R3_LL
        and rt["metric"] < 65535,
        count=15,
    )

    # r3 genuinely advertises P (seqno H3): unfeasible, B stays finite
    r3.cmd("ip addr add 10.98.0.1/32 dev lo")
    rtB = wait_route(r1, route_is_B_unfeasible, count=30)
    logger.info("route B unfeasible: %s", rtB["raw"])


def test_setup_infinity_route():
    "Retract A via an outbound deny on r2; A stays installed with INFINITY."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list DENYP seq 5 deny {}\n".format(P_PLEN)
        + "ip prefix-list DENYP seq 10 permit any\n"
        "router babel\n"
        "distribute-list prefix DENYP out r2-eth0\n"
    )
    rtA = wait_route(r1, route_is_A_infinity, count=30)
    logger.info("route A retracted: %s", rtA["raw"])
    # let r1's own post-retraction request retransmits settle
    time.sleep(SETTLE_S)


def test_c2_no_trigger():
    "Without a request there is no answer and no forwarded request."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    off0 = log_len(r1)
    time.sleep(6)
    assert log_count(r1, off0, ANSWER_NEEDLE) == 0
    assert log_count(r1, off0, FORWARD_NEEDLE) == 0


def test_t1_request_not_answered_with_retraction():
    "T1: INFINITY installed route must not satisfy the request; it forwards."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    win = request_probe(
        r1, h1, state["rid2"], state["seqnoA"], 16, "T1 infinity-route request"
    )
    answers = log_count(r1, win["off0"], ANSWER_NEEDLE)
    forwards = log_count(r1, win["off0"], FORWARD_NEEDLE)
    state["T1"] = win
    assert answers == 0, "request was answered although the route metric is INFINITY"
    assert forwards >= 1, "request was not forwarded to r3"


def test_t2_hop_count_exhausted():
    "T2: hop count 1 must be dropped silently, not answered."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    win = request_probe(
        r1, h1, state["rid2"], state["seqnoA"], 1, "T2 hop-count-1 request"
    )
    answers = log_count(r1, win["off0"], ANSWER_NEEDLE)
    forwards = log_count(r1, win["off0"], FORWARD_NEEDLE)
    state["T2"] = win
    assert answers == 0, "hop-count-1 request was answered with a retraction"
    assert forwards == 0, "hop-count-1 request was forwarded"


def test_t3_other_router_id():
    "T3: a different router-id must not be answered with a retraction either."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    win = request_probe(
        r1, h1, state["rid3"], state["seqnoA"], 16, "T3 other-router-id request"
    )
    answers = log_count(r1, win["off0"], ANSWER_NEEDLE)
    forwards = log_count(r1, win["off0"], FORWARD_NEEDLE)
    state["T3"] = win
    assert answers == 0, "other-router-id request was answered with a retraction"
    assert forwards >= 1, "other-router-id request was not forwarded to r3"


def test_wire_evidence():
    "The r1-eth1 pcap corroborates the debug-log path evidence."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    stop_record(r1, state["rec_pid"])
    records = parse_pcap(state["pcap"])
    assert records, "no packets captured on r1-eth1"

    ev = wire_evidence(records, state["C1"])
    logger.info("C1 wire evidence: %s", ev)
    assert ev["injected_request"] == 1, "C1: request missing from capture"
    assert ev["r1_finite_update_P"] >= 1, "C1: no finite-metric update on the wire"
    assert ev["r1_infinity_answer"] == 0, "C1: unexpected INFINITY update on the wire"

    for key in ["T1", "T2", "T3"]:
        ev = wire_evidence(records, state[key])
        logger.info("%s wire evidence: %s", key, ev)
        assert ev["injected_request"] == 1, "{}: request missing from capture".format(
            key
        )
        assert (
            ev["r1_infinity_answer"] == 0
        ), "{}: INFINITY update answered on the wire".format(key)
    for key in ["T1", "T3"]:
        ev = wire_evidence(records, state[key])
        assert (
            ev["r1_forward_hop15"] >= 1
        ), "{}: no forwarded request on the wire".format(key)
    ev = wire_evidence(records, state["T2"])
    assert (
        ev["r1_forward_hop15"] == 0
    ), "T2: hop-count-1 request was forwarded on the wire"


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
