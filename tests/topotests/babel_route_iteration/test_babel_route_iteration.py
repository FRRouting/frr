#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_route_iteration.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_babel_route_iteration.py
=============================

Regression for babeld skipping routes while iterating a slot's route
list when the iteration itself reorders the list.

A babeld slot (one prefix) is a linked list with the installed route at
its head.  route_changed() may install a better route and
move_installed_route() then moves that route to the head of the slot,
rewriting the predecessor's next pointer.  An iterator positioned on the
predecessor follows the rewritten next pointer and never visits the
moved route:

  - retract_neighbour_routes() (wildcard retraction, RFC 8966 s4.6.9)
    retracts route A, route_changed(A) installs the finite-metric
    fallback B and moves it in front of A; B is never retracted and
    keeps its finite metric and installed state;
  - update_neighbour_metric() (e.g. after an IHU raises txcost) updates
    A's metric, route_changed(A) switches to the stale-metric B and
    moves it in front of A; B is never updated and keeps a too-low
    metric while installed.

The same iterator invalidation is hardened in update_interface_metric()
and expire_routes(); those loops have no runtime-reachable trigger with
matching routes (see the commit message), so this test covers the two
reachable paths plus the legal-retraction and normal-selection controls.

Topology
--------

    a1 (attacker) ---- sw1 ---- r1 ---- sw2 ---- r2

r2 redistributes loopback 10.99.1.1/32 (normal-selection control).  a1
speaks enough Babel to be a neighbour (3 Hellos, IHU txcost=100), then
injects Updates with router-id 00:00:00:00:00:00:00:99:

  route A: Update AE=1 P seqno=100 metric=100, Next-Hop 10.13.0.2
  route B: Update AE=1 P seqno=101 metric=300, Next-Hop 10.13.0.3

Both routes share (prefix, neighbour) and differ only in nexthop, so
they live in one slot.  On the wired interface the neighbour cost is
the advertised txcost (100), giving metric(A)=200 and metric(B)=400.

Metric smoothing is disabled on both routers (babel smoothing-half-life
0).  With the default half-life (4s) the initial smoothed_metric of a
new route (32768) decays toward the route metric through roughly()
randomised steps, so find_best_route()'s hysteresis comparison between
A and B is random at IHU time: the route_changed() switch that drives
the iterator skip only happens when B happens to win the comparison.
With smoothing off the comparison is deterministic and the skip is
exercised on every run.
"""

import os
import re
import sys
import time

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.babeld]

P_W = "10.99.0.0/24"    # wildcard retraction scenario
P_I = "10.99.2.0/24"    # neighbour-metric scenario
P_S = "10.99.3.0/24"    # specific-retraction control
P_CTRL = "10.99.1.1/32"  # r2 loopback, normal-selection control
RID = "00:00:00:00:00:00:00:99"
NH_A = "10.13.0.2"
NH_B = "10.13.0.3"
TXCOST0 = 100
TXCOST1 = 5000
M_A = TXCOST0 + 100     # 200
M_B = TXCOST0 + 300     # 400
M_A1 = TXCOST1 + 100    # 5100
M_B1 = TXCOST1 + 300    # 5300
INFINITY = 65535


def build_topo(tgen):
    a1 = tgen.add_host("a1", "10.13.0.2/24", "via 10.13.0.1")
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(a1)
    sw1.add_link(r1)

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(r2)


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
    a1.cmd("ip -6 addr add fe80::a1/64 dev a1-eth0 2>/dev/null || true")
    a1.cmd("ip addr add {}/24 dev a1-eth0 2>/dev/null || true".format(NH_B))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


ROUTE_RE = re.compile(
    r"^(\S+) metric (\d+) refmetric (\d+) id ((?:[0-9a-f]{2}:){7}[0-9a-f]{2}) "
    r"seqno (\d+).*via (\S+) neigh (\S+)(.*)$"
)
NEXTHOP_RE = re.compile(r"nexthop (\S+)")


def _routes(router):
    """Parse 'show babel route' into {prefix: [route, ...]}; the list
    mirrors the slot's linked-list order."""
    out = router.vtysh_cmd("show babel route")
    routes = {}
    for ln in out.splitlines():
        m = ROUTE_RE.match(ln.strip())
        if not m:
            continue
        rest = m.group(8)
        nh = NEXTHOP_RE.search(rest)
        routes.setdefault(m.group(1), []).append(
            {
                "metric": int(m.group(2)),
                "refmetric": int(m.group(3)),
                "seqno": int(m.group(5)),
                "neigh": m.group(7),
                "nexthop": nh.group(1) if nh else m.group(7),
                "installed": "installed" in rest,
                "raw": ln.strip(),
            }
        )
    return routes


def _send(jobs):
    a1 = get_topogen().gears["a1"]
    out = a1.cmd(
        "python3 {}/send_babel.py a1-eth0 {}".format(CWD, " ".join(jobs))
    )
    logger.info("send_babel: %s", out.strip())


def _pair(routes, pfx):
    """Return (route A, route B) for the two injected nexthops."""
    a = [r for r in routes.get(pfx, []) if r["nexthop"] == NH_A]
    b = [r for r in routes.get(pfx, []) if r["nexthop"] == NH_B]
    return (a[0] if len(a) == 1 else None, b[0] if len(b) == 1 else None)


def _setup_pair(pfx4, plen):
    """Hello x3, IHU txcost=100, route A (installed) + route B (fallback)."""
    _send(["hello,3", "ihu,{}".format(TXCOST0),
           "routes,{},{},{},100,100,101,300".format(RID, pfx4, plen)])

    def check():
        a, b = _pair(_routes(get_topogen().gears["r1"]), "{}/{}".format(pfx4, plen))
        if not (a and b):
            return "routes not created"
        if not (a["installed"] and not b["installed"]):
            return "A not installed or B unexpectedly installed: {} | {}".format(
                a["raw"], b["raw"]
            )
        if a["metric"] != M_A or b["metric"] != M_B:
            return "unexpected metrics: {} | {}".format(a["raw"], b["raw"])
        return None

    _, result = topotest.run_and_expect(check, None, count=20, wait=0.5)
    assert result is None, "failed to build A(installed)+B(fallback): {}".format(result)


def _routes_seen(router, pfx, pred, seconds):
    """Poll for `seconds`; return the routes observed for pfx matching
    pred at any poll."""
    seen = {}
    deadline = time.time() + seconds
    while True:
        for r in _routes(router).get(pfx, []):
            if pred(r):
                seen[r["raw"]] = True
        if time.time() >= deadline:
            return list(seen)
        time.sleep(0.5)


def _zebra_metric(router, pfx):
    """Return the zebra RIB metric for pfx, or None when absent."""
    out = router.vtysh_cmd("show ip route {}".format(pfx.split("/")[0]))
    if "Routing entry" not in out:
        return None
    m = re.search(r"metric (\d+)", out)
    return int(m.group(1)) if m else None


def test_converge():
    "Baseline: r1 installs the control loopback via r2 with finite metric"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check():
        routes = _routes(r1).get(P_CTRL, [])
        if not any(r["installed"] and r["metric"] < INFINITY for r in routes):
            return "control route not installed yet"
        return None

    _, result = topotest.run_and_expect(check, None, count=90, wait=1)
    assert result is None, "r1 failed to install the control route"


def test_wildcard_retraction_retracts_all_routes():
    "Wildcard retraction must also retract the moved fallback route B"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _setup_pair("10.99.0.0", 24)

    _send(["wildcard"])

    # Within 5s (the buggy route is retracted ~10s later only by an
    # unrelated txcost reset, so the window is decisive): no route for
    # P_W may keep a finite metric.
    finite = _routes_seen(r1, P_W, lambda r: r["metric"] < INFINITY, seconds=5)
    assert finite == [], "routes kept finite metric after wildcard retraction: {}".format(
        finite
    )

    # zebra must not keep a finite-metric route either.
    metric = _zebra_metric(r1, P_W)
    assert metric is None or metric in (0, INFINITY), (
        "zebra kept finite-metric route after wildcard retraction: metric {}".format(metric)
    )

    # The downstream router must not learn a finite-metric route.
    finite_r2 = _routes_seen(r2, P_W, lambda r: r["metric"] < INFINITY, seconds=5)
    assert finite_r2 == [], "r2 learned a finite-metric route: {}".format(finite_r2)

    # Control prefix is untouched (normal selection).
    routes = _routes(r1).get(P_CTRL, [])
    assert any(r["installed"] and r["metric"] < INFINITY for r in routes), (
        "control route lost after wildcard retraction"
    )


def test_neighbour_metric_update_covers_all_routes():
    "IHU-driven metric update must also update the moved fallback route B"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _setup_pair("10.99.2.0", 24)

    _send(["ihu,{}".format(TXCOST1)])

    # Within 5s: no route for P_I may keep a pre-IHU metric.
    stale = _routes_seen(
        r1, P_I, lambda r: r["metric"] in (M_A, M_B), seconds=5
    )
    assert stale == [], "routes kept stale metric after IHU: {}".format(stale)

    # Both routes must carry the updated metrics.
    def check():
        routes = _routes(r1).get(P_I, [])
        metrics = sorted(r["metric"] for r in routes)
        if metrics != sorted([M_A1, M_B1]):
            return "expected metrics [{}, {}], got {}".format(M_A1, M_B1, metrics)
        return None

    _, result = topotest.run_and_expect(check, None, count=10, wait=0.5)
    assert result is None, "metrics not updated after IHU: {}".format(result)

    # zebra must not keep the stale metric.
    metric = _zebra_metric(r1, P_I)
    assert metric is None or metric != M_B, (
        "zebra kept stale metric after IHU: metric {}".format(metric)
    )


def test_specific_retraction_still_works():
    "Legal (non-wildcard) retraction must retract the route on all versions"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _send(["route,{},{},24,100,100,{}".format(RID, "10.99.3.0", NH_A)])

    def installed():
        routes = _routes(r1).get(P_S, [])
        return "route not installed" if not any(
            r["installed"] for r in routes
        ) else None

    _, result = topotest.run_and_expect(installed, None, count=20, wait=0.5)
    assert result is None, "failed to install the control route"

    _send(["retract,{},{},24,100,{}".format(RID, "10.99.3.0", NH_A)])

    finite = _routes_seen(r1, P_S, lambda r: r["metric"] < INFINITY, seconds=5)
    assert finite == [], "specific retraction left finite routes: {}".format(finite)

    # Control prefix is untouched (normal selection).
    routes = _routes(r1).get(P_CTRL, [])
    assert any(r["installed"] and r["metric"] < INFINITY for r in routes), (
        "control route lost after specific retraction"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
