#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
RIP: RIPv2 indirect next-hop validation must not trust dead or
off-interface routes, and a RIB entry must be bound to the interface its
next hop is actually reachable on.

rip_response_process() resolves a non-directly-connected RIPv2 next hop
through route_node_match() on the RIP RIB, but only checks the matched
route's type/subtype before trusting rinfo->from: a route with metric 16
(pending garbage collection) still vouches for the next hop, and a route
learned on another interface yields an entry whose gateway lives on that
other interface while rip_rte_process() stamps nh.ifindex with the
ingress interface.  ZAPI carries only the gateway, but ripd's split
horizon and next-hop-out derivation trust nh.ifindex, so the route is
advertised to the very router it points at: an r1<->r2 loop.

Topology: r1 (victim) with r1-eth0 to r2 and r1-eth1 to attacker h1.
A helper on r2 impersonates the RIP speaker that owns the covering
routes 198.51.100.1/32 and 198.51.100.2/32.  Timers are 5/30/15
(update/timeout/garbage) to keep the test short.
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

R1_ETH0_IP = "10.0.12.1"
R2_ETH0_IP = "10.0.12.2"
R1_ETH1_IP = "10.0.13.1"
H1_IP = "10.0.13.3"
R2_LO_IP = "10.254.254.1"
MASK = "255.255.255.0"
HOST_MASK = "255.255.255.255"

N1 = "198.18.11.1"      # covering route for the legal-recursion control
N2 = "198.51.100.1"     # covering route for the dead-route test (r2 helper)
N3 = "198.51.100.2"     # covering route for the cross-interface test
NH_R2 = R2_ETH0_IP      # directly reachable next hop on another interface
NH_NONE = "203.0.113.99"  # next hop with no covering route

P_LEGAL = "198.18.11.0/24"
P_DEAD = "198.18.12.0/24"
P_CROSS = "198.18.13.0/24"
P_DIRECT = "198.18.14.0/24"
P_UNREACH = "198.18.15.0/24"
# ping targets live on h1 so a delivered packet gets a reply
T_CROSS = "198.18.13.1"

PROCS = []


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    s1 = tgen.add_switch("s1")
    s1.add_link(r1)
    s1.add_link(r2)
    s2 = tgen.add_switch("s2")
    s2.add_link(r1)
    h1 = tgen.add_host("h1", "{}/24".format(H1_IP),
                       "via {}".format(R1_ETH1_IP))
    s2.add_link(h1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()

    h1 = tgen.gears["h1"]
    for target in ("198.18.11.1", "198.18.12.1", T_CROSS, "198.18.14.1",
                   "198.18.15.1"):
        h1.cmd_raises("ip addr add {}/24 dev h1-eth0".format(target))


def teardown_module(mod):
    tgen = get_topogen()

    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _pkt(prefix, nexthop, metric, at, src=None, mask=MASK):
    spec = {"prefix": prefix.split("/")[0], "mask": mask, "nexthop": nexthop,
            "metric": metric, "tag": 0, "at": at}
    if src:
        spec["src"] = src
    return spec


def _send(tgen, rname, packets, tag, iface, src, dst):
    """Start rip_send.py on the given gear; returns the popen object."""
    node = tgen.gears[rname]
    wire_packets = []
    for p in packets:
        spec = {"prefix": p["prefix"], "mask": p["mask"],
                "nexthop": p["nexthop"], "metric": p["metric"],
                "tag": p["tag"], "at": p["at"]}
        if p.get("src") and p["src"] != src:
            spec["src"] = p["src"]
        wire_packets.append(spec)
    spec = {"iface": iface, "src": src, "dst": dst, "packets": wire_packets}
    spec_path = os.path.join(node.logdir, "rip_send_{}.json".format(tag))
    with open(spec_path, "w") as fp:
        json.dump(spec, fp)
    log_path = os.path.join(node.logdir, "rip_send_{}.log".format(tag))
    proc = node.popen(["python3", os.path.join(CWD, "rip_send.py"), spec_path],
                      stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
    PROCS.append(proc)
    return proc


def _send_h1(tgen, packets, tag):
    return _send(tgen, "h1", packets, tag, "h1-eth0", H1_IP, R1_ETH1_IP)


def _send_r2(tgen, packets, tag):
    return _send(tgen, "r2", packets, tag, "r2-eth0", R2_ETH0_IP, R1_ETH0_IP)


def _route_entries(node, prefix):
    """zebra RIB entries for prefix: [] when not installed."""
    output = node.vtysh_cmd("show ip route {} json".format(prefix))
    start = output.find("{")
    if start < 0:
        return []
    return json.loads(output[start:]).get(prefix, [])


def _poll_route(node, prefix, seconds, interval=1.0):
    """Poll the zebra RIB every `interval`; returns [{t, nhs, metric}]."""
    samples = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        entries = _route_entries(node, prefix)
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


def _require_r2_lo(tgen):
    """Baseline: r1 learns r2's loopback through normal RIP operation."""
    r1 = tgen.gears["r1"]

    def _check():
        entries = _route_entries(r1, "{}/32".format(R2_LO_IP))
        if entries and R2_ETH0_IP in [nh.get("ip")
                                      for nh in entries[0].get("nexthops", [])]:
            return None
        return "missing"

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "r1 never learned {}/32 from r2".format(R2_LO_IP)


def _assert_nexthops(samples, t0, since, want, label):
    want = sorted(want)
    problems = ["t=+{:.0f}s nexthops {} != {}".format(
        s["t"] - t0, sorted(s["nhs"]), want)
        for s in samples if s["t"] - t0 >= since and sorted(s["nhs"]) != want]
    assert not problems, "{}: {}".format(label, "; ".join(problems[:5]))


def test_legal_recursion_same_interface(tgen):
    """Control: a covering route learned on the arrival interface may
    resolve the next hop to its originator (RFC 2453 4.4)."""
    _require_r2_lo(tgen)
    r1 = tgen.gears["r1"]
    packets = [_pkt(N1, "0.0.0.0", 2, at=t, mask=HOST_MASK)
               for t in (0, 3, 6)]
    packets += [_pkt(P_LEGAL, N1, 2, at=t) for t in (1, 4, 7)]

    t0 = time.time()
    proc = _send_h1(tgen, packets, "legal")
    samples = _poll_route(r1, P_LEGAL, 14)
    proc.wait(timeout=30)

    _assert_nexthops(samples, t0, 8, [H1_IP], "legal recursion")


def test_dead_route_nexthop_fallback(tgen):
    """A covering route poisoned to metric 16 must not validate a next
    hop; the next hop falls back to the packet's originator."""
    _require_r2_lo(tgen)
    r1 = tgen.gears["r1"]
    # Covering route alive, then poisoned: the metric-16 entry stays in
    # the RIP RIB for the garbage time.
    cover = [_pkt(N2, "0.0.0.0", 2, at=t, src=R2_ETH0_IP, mask=HOST_MASK)
             for t in (0, 3, 6)]
    proc = _send_r2(tgen, cover, "dead_cover")
    proc.wait(timeout=30)
    _, result = topotest.run_and_expect(
        lambda: None if any(R2_ETH0_IP in s["nhs"] for s in
                            _poll_route(r1, "{}/32".format(N2), 2))
        else "missing", None, count=20, wait=1)
    assert result is None, "covering route {}/32 never installed".format(N2)

    poison = [_pkt(N2, "0.0.0.0", 16, at=0, src=R2_ETH0_IP, mask=HOST_MASK)]
    proc = _send_r2(tgen, poison, "dead_poison")
    proc.wait(timeout=30)
    _, result = topotest.run_and_expect(
        lambda: None if _rip_rib_metric(r1, "{}/32".format(N2)) == 16
        else "missing", None, count=10, wait=1)
    assert result is None, "covering route never poisoned to metric 16"

    attack = [_pkt(P_DEAD, N2, 2, at=t) for t in (0, 3, 6, 9, 12)]
    t0 = time.time()
    proc = _send_h1(tgen, attack, "dead_attack")
    samples = _poll_route(r1, P_DEAD, 15)
    proc.wait(timeout=30)

    # RFC 2453 4.4: the next hop is not directly reachable, so the route
    # must be via the originator (10.0.13.3), not the dead route's
    # originator (10.0.12.2).
    _assert_nexthops(samples, t0, 8, [H1_IP], "dead route next hop")


def test_cross_interface_nexthop_no_loop(tgen):
    """A covering route learned on a different interface must not
    validate the next hop; falling back to the sender also keeps r1 from
    readvertising the route to the router it pointed at (loop)."""
    _require_r2_lo(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    cover = [_pkt(N3, "0.0.0.0", 2, at=t, src=R2_ETH0_IP, mask=HOST_MASK)
             for t in range(0, 36, 3)]
    proc_cover = _send_r2(tgen, cover, "cross_cover")
    attack = [_pkt(P_CROSS, N3, 2, at=t) for t in (2, 5, 8, 11, 14)]
    t0 = time.time()
    proc = _send_h1(tgen, attack, "cross_attack")
    samples = _poll_route(r1, P_CROSS, 15)
    proc.wait(timeout=30)

    _assert_nexthops(samples, t0, 8, [H1_IP], "cross-interface next hop")

    # On both versions r2 may learn the prefix from r1; with the fix the
    # traffic is delivered to h1 instead of looping between r1 and r2.
    r2_samples = _poll_route(r2, P_CROSS, 5)
    assert any(s["nhs"] == [R1_ETH0_IP] for s in r2_samples), \
        "r2 never learned {} via r1".format(P_CROSS)
    out = r2.cmd("ping -c 2 -W 2 {}".format(T_CROSS))
    assert " 0% packet loss" in out, \
        "ping r2->{} did not reach h1 (loop?): {}".format(T_CROSS, out[-300:])
    proc_cover.terminate()


def test_direct_nexthop_other_interface(tgen):
    """A directly reachable next hop on another interface is RFC-legal;
    the entry must still be bound to the gateway's interface so split
    horizon keeps r1 from advertising the route back to that router."""
    _require_r2_lo(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    attack = [_pkt(P_DIRECT, NH_R2, 2, at=t) for t in (0, 3, 6, 9, 12)]
    t0 = time.time()
    proc = _send_h1(tgen, attack, "direct")
    samples = _poll_route(r1, P_DIRECT, 15)
    proc.wait(timeout=30)

    _assert_nexthops(samples, t0, 8, [NH_R2], "direct next hop on r1")

    # r1 must not advertise the route out the interface its next hop is
    # on; r2 therefore never learns it.  Unpatched, the mismatched
    # nh.ifindex makes r1 advertise it to r2, which installs it via r1
    # and loops.
    r2_samples = _poll_route(r2, P_DIRECT, 10)
    learned = [s for s in r2_samples if s["nhs"]]
    assert not learned, "r2 learned {} via r1: {}".format(
        P_DIRECT, [s["nhs"] for s in learned[:5]])


def test_unreachable_nexthop_fallback(tgen):
    """Control: a next hop with no covering route falls back to the
    packet's originator."""
    _require_r2_lo(tgen)
    r1 = tgen.gears["r1"]
    attack = [_pkt(P_UNREACH, NH_NONE, 2, at=t) for t in (0, 3, 6)]
    t0 = time.time()
    proc = _send_h1(tgen, attack, "unreach")
    samples = _poll_route(r1, P_UNREACH, 12)
    proc.wait(timeout=30)

    _assert_nexthops(samples, t0, 8, [H1_IP], "unreachable next hop")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
