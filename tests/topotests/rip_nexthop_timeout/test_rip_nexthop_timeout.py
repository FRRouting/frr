#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
RIP: a same-router update that only changes the next hop must update the
path and refresh the route timeout.

With the default allow-ecmp=0, rip_rte_process() matches an existing path
by (from, gateway).  An update that keeps prefix, metric, distance and
ingress interface but changes only the next hop fails that match, and
rip_ecmp_add() then drops it without touching the old entry: the old
path's timeout is never refreshed and rip_timeout() withdraws the route
(zebra DELETE) even though the neighbor kept advertising it.

Topology: r1 (victim) and r2 (RIP speaker, 203.0.113.1/32) on s1, plus
attacker host h1.  r1 learns 203.0.113.1/32 from r2, so a next hop of
203.0.113.1 in h1's updates is rewritten to r2's address (10.0.12.2) by
the next-hop validation, while 0.0.0.0 is stored as the packet originator
(10.0.12.3).  Timers are 5/30/15 (update/timeout/garbage) to keep the
test short.
"""

import json
import os
import shutil
import subprocess
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripd]

R1_IP = "10.0.12.1"
H1_IP = "10.0.12.3"
H1_IP2 = "10.0.12.4"
NH_A = H1_IP               # stored next hop for next-hop field 0.0.0.0
NH_B = "10.0.12.2"         # stored next hop for next-hop field 203.0.113.1
NH_FIELD_A = "0.0.0.0"
NH_FIELD_B = "203.0.113.1"
R2_LO_IP = "203.0.113.1"
MASK = "255.255.255.0"

PROCS = []


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)
    h1 = tgen.add_host("h1", "10.0.12.3/24", "via 10.0.12.1")
    switch.add_link(h1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()

    tgen.gears["h1"].cmd_raises("ip addr add 10.0.12.4/24 dev h1-eth0")


def teardown_module(mod):
    tgen = get_topogen()

    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _pkt(prefix, nexthop, metric, at, src=H1_IP):
    return {"prefix": prefix.split("/")[0], "mask": MASK, "nexthop": nexthop,
            "metric": metric, "tag": 0, "at": at, "src": src}


def _send(tgen, packets, tag):
    """Start rip_send.py on h1; returns the popen object."""
    h1 = tgen.gears["h1"]
    wire_packets = []
    for p in packets:
        spec = {"prefix": p["prefix"], "mask": p["mask"],
                "nexthop": p["nexthop"], "metric": p["metric"],
                "tag": p["tag"], "at": p["at"]}
        if p["src"] != H1_IP:
            spec["src"] = p["src"]
        wire_packets.append(spec)
    spec = {"iface": "h1-eth0", "src": H1_IP, "dst": R1_IP,
            "packets": wire_packets}
    spec_path = os.path.join(h1.logdir, "rip_send_{}.json".format(tag))
    with open(spec_path, "w") as fp:
        json.dump(spec, fp)
    log_path = os.path.join(h1.logdir, "rip_send_{}.log".format(tag))
    proc = h1.popen(["python3", os.path.join(CWD, "rip_send.py"), spec_path],
                    stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
    PROCS.append(proc)
    return proc


def _route_entries(r1, prefix):
    """zebra RIB entries for prefix: [] when not installed."""
    output = r1.vtysh_cmd("show ip route {} json".format(prefix))
    start = output.find("{")
    if start < 0:
        return []
    return json.loads(output[start:]).get(prefix, [])


def _poll_route(r1, prefix, seconds, interval=1.0):
    """Poll the zebra RIB every `interval`; returns [{t, nhs, metric}]."""
    samples = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        entries = _route_entries(r1, prefix)
        nhs, metric = [], None
        if entries:
            metric = entries[0].get("metric")
            nhs = [nh.get("ip") for nh in entries[0].get("nexthops", [])
                   if nh.get("ip")]
        samples.append({"t": time.time(), "nhs": nhs, "metric": metric})
        time.sleep(interval)
    return samples


def _rip_rib_metric(r1, prefix):
    """RIP RIB metric for prefix from operational data, or None."""
    xpath = ("/frr-ripd:ripd/instance[vrf='default']"
             "/state/routes/route[prefix='{}']".format(prefix))
    try:
        output = json.loads(
            r1.vtysh_cmd("show yang operational-data {} ripd".format(xpath)))
        routes = output["frr-ripd:ripd"]["instance"][0]["state"]["routes"][
            "route"]
    except Exception:
        return None
    if isinstance(routes, dict):
        routes = [routes]
    for route in routes:
        if route.get("prefix") == prefix:
            return route.get("metric")
    return None


def _require_r2_route(tgen):
    """The next-hop-B rewrite needs r2's loopback as an RTE route on r1."""
    r1 = tgen.gears["r1"]

    def _check():
        entries = _route_entries(r1, "{}/32".format(R2_LO_IP))
        if entries and NH_B in [nh.get("ip")
                                for nh in entries[0].get("nexthops", [])]:
            return None
        return "missing"

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "r1 never learned {}/32 from r2".format(R2_LO_IP)


def _assert_never_missing(samples, t0, label):
    first = next((i for i, s in enumerate(samples) if s["nhs"]), None)
    assert first is not None, "{}: route never installed".format(label)
    problems = ["t=+{:.0f}s route missing".format(s["t"] - t0)
                for s in samples[first:] if not s["nhs"]]
    assert not problems, "{}: {}".format(label, "; ".join(problems[:5]))


def _assert_nexthops(samples, t0, since, want, label):
    want = sorted(want)
    problems = ["t=+{:.0f}s nexthops {} != {}".format(
        s["t"] - t0, sorted(s["nhs"]), want)
        for s in samples if s["t"] - t0 >= since and sorted(s["nhs"]) != want]
    assert not problems, "{}: {}".format(label, "; ".join(problems[:5]))


def test_rip_nexthop_change_keeps_route(tgen):
    """R7 regression: only the next hop changes; the route must survive."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.2.0/24"
    packets = [_pkt(prefix, NH_FIELD_A, 2, at=0)]
    packets += [_pkt(prefix, NH_FIELD_B, 2, at=t)
                for t in list(range(4, 53, 4)) + [68, 72]]

    t0 = time.time()
    proc = _send(tgen, packets, "nexthop_change")
    samples = _poll_route(r1, prefix, 80)
    proc.wait(timeout=30)

    _assert_never_missing(samples, t0, "nexthop change")
    _assert_nexthops(samples, t0, 8, [NH_B], "nexthop change")


def test_rip_same_nexthop_refresh(tgen):
    """Control: identical updates keep the route alive past the timeout."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.1.0/24"
    packets = [_pkt(prefix, NH_FIELD_A, 2, at=t) for t in range(0, 45, 4)]

    t0 = time.time()
    proc = _send(tgen, packets, "same_nexthop")
    samples = _poll_route(r1, prefix, 50)
    proc.wait(timeout=30)

    _assert_never_missing(samples, t0, "same nexthop")
    _assert_nexthops(samples, t0, 5, [NH_A], "same nexthop")


def test_rip_metric_change(tgen):
    """Control: a metric change from the same router updates the RIB."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.3.0/24"
    packets = [_pkt(prefix, NH_FIELD_A, 2, at=0)]
    packets += [_pkt(prefix, NH_FIELD_A, 3, at=t) for t in range(4, 45, 4)]

    t0 = time.time()
    proc = _send(tgen, packets, "metric_change")
    samples = _poll_route(r1, prefix, 50)
    proc.wait(timeout=30)

    _assert_never_missing(samples, t0, "metric change")
    first4 = next((s for s in samples if s["metric"] == 4), None)
    assert first4 is not None, "metric change: zebra metric never became 4"
    assert 3 <= first4["t"] - t0 <= 10, \
        "metric change: metric became 4 at unexpected time t=+{:.0f}s".format(
            first4["t"] - t0)
    before = [s for s in samples if s["t"] < first4["t"] and s["nhs"]]
    assert all(s["metric"] == 3 for s in before), \
        "metric change: initial zebra metric is not 3"
    late = [s for s in samples if s["t"] - t0 >= 8]
    assert late and all(s["metric"] == 4 for s in late), \
        "metric change: zebra metric did not stay 4: {}".format(
            [s["metric"] for s in late[:5]])


def test_rip_ecmp_two_paths(tgen):
    """Control: allow-ecmp 2 installs both next hops and keeps them."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.4.0/24"
    r1.vtysh_cmd("configure terminal\nrouter rip\nallow-ecmp 2\n")
    packets = [_pkt(prefix, NH_FIELD_A if i % 2 == 0 else NH_FIELD_B, 2,
                    at=4 * i)
               for i in range(12)]

    t0 = time.time()
    proc = _send(tgen, packets, "ecmp")
    samples = _poll_route(r1, prefix, 50)
    proc.wait(timeout=30)

    _assert_never_missing(samples, t0, "ecmp")
    _assert_nexthops(samples, t0, 10, [NH_A, NH_B], "ecmp")

    # Cleanup: withdraw both paths, wait for GC, restore allow-ecmp 0.
    withdraw = [_pkt(prefix, NH_FIELD_A, 16, at=0),
                _pkt(prefix, NH_FIELD_B, 16, at=2)]
    proc = _send(tgen, withdraw, "ecmp_withdraw")
    proc.wait(timeout=30)
    time.sleep(20)
    r1.vtysh_cmd("configure terminal\nrouter rip\nno allow-ecmp\n")


def test_rip_withdraw(tgen):
    """Control: metric 16 withdraws the route and the entry is GC'd."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.5.0/24"
    packets = [_pkt(prefix, NH_FIELD_A, 2, at=0),
               _pkt(prefix, NH_FIELD_A, 16, at=4)]

    t0 = time.time()
    proc = _send(tgen, packets, "withdraw")
    samples = _poll_route(r1, prefix, 10)
    proc.wait(timeout=30)

    first = next((i for i, s in enumerate(samples) if s["nhs"]), None)
    assert first is not None, "withdraw: route never installed"
    problems = ["t=+{:.0f}s route still installed".format(s["t"] - t0)
                for s in samples if s["t"] - t0 >= 8 and s["nhs"]]
    assert not problems, "withdraw: {}".format("; ".join(problems[:5]))

    # The poisoned entry (metric 16) stays in the RIP RIB for the garbage
    # time (15s) before it is collected.
    assert _rip_rib_metric(r1, prefix) == 16, \
        "withdraw: poisoned entry missing from RIP RIB"
    deadline = time.time() + 25
    while time.time() < deadline:
        if _rip_rib_metric(r1, prefix) is None:
            break
        time.sleep(1)
    assert _rip_rib_metric(r1, prefix) is None, \
        "withdraw: entry not garbage-collected"


def test_rip_other_source_expires(tgen):
    """Control: updates from another source must not refresh the route."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.6.0/24"
    packets = [_pkt(prefix, NH_FIELD_A, 2, at=0, src=H1_IP)]
    packets += [_pkt(prefix, NH_FIELD_B, 2, at=t, src=H1_IP2)
                for t in range(4, 45, 4)]

    t0 = time.time()
    proc = _send(tgen, packets, "other_source")
    samples = _poll_route(r1, prefix, 50)
    proc.wait(timeout=30)

    early = [s for s in samples if 3 <= s["t"] - t0 < 28]
    assert early and all(s["nhs"] == [NH_A] for s in early), \
        "other source: route disturbed: {}".format(
            [s["nhs"] for s in early[:5]])
    # 10.0.13.3's route must expire on its original schedule (10.0.13.4's
    # updates cannot refresh it); the flip to nexthop B is 10.0.13.4's own
    # route re-added after the expiry.
    late = [s for s in samples if s["t"] - t0 >= 36]
    assert late and all(s["nhs"] == [NH_B] for s in late), \
        "other source: route not re-added by {}: {}".format(
            H1_IP2, [s["nhs"] for s in late[:5]])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
