#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_source_refcount.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_source_refcount.py: one Babel source must survive 65,536 routes.

A Babel source (router-id, prefix, plen) is retained once per route object
created for it.  At baseline (c4e94c4aaa) route_count is a 16-bit field and
retain_source() asserts route_count < 0xffff, so a remote Update sequence
that keeps passing update_feasible() aborts babeld on the 65,536th route:
update_feasible() accepts every Update carrying the source's seqno with any
refmetric below INFINITY, because src->metric is only ever written at
source creation (metric = INFINITY) and by update_source() on the send
path -- a receive-only source never leaves metric INFINITY.  Routes are
keyed by (prefix, plen, neighbour, nexthop), so one neighbour, one prefix,
one seqno and one distinct next-hop per route yields one retain per route.

Topology (one broadcast domain):

    r1-eth0 (victim) -- sw1 -- r2-eth0 (legit peer)
    h1-eth0 (packet injector) -- sw1

Checks:
  * mechanism: a small batch (40 routes) grows the route table by exactly
    40; duplicate next-hop updates are deduplicated, an older seqno is
    rejected, a retraction for an unknown next-hop creates nothing, and a
    same-seqno update with refmetric 65534 is accepted -- direct evidence
    that src->metric never left INFINITY; routes and the attacker
    neighbour persist across neighbour-check ticks;
  * boundary: 65,536 routes for one fresh source must not abort babeld.
    At baseline the daemon dies exactly at the 65,536th retain_source().
"""

import os
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.babeld]

PEER_LL = None
SEQNO = 100
MECH_PREFIX = "20010db800630000"   # 2001:db8:63::/64
BOUND_PREFIX = "20010db800640000"  # 2001:db8:64::/64
MECH_STR = "2001:db8:63::/64"
BOUND_STR = "2001:db8:64::/64"
N_MECH = 40
N_FULL = 65536
PER_PACKET = 40
FLOOD_GAP = 0.03


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("h1", "10.99.0.3/24", "via 10.99.0.1")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    "Sets up the pytest environment"
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

    tgen.start_router()

    h1 = tgen.gears["h1"]
    h1.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=0")
    h1.cmd("sysctl -qw net.ipv6.conf.h1-eth0.disable_ipv6=0")
    h1.cmd("ip -6 addr add fe80::a1/64 dev h1-eth0 2>/dev/null || true")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def neighbour_lines(r1):
    out = r1.vtysh_cmd("show babel neighbor")
    return [ln for ln in out.splitlines() if ln.startswith("Neighbour ")]


def route_count(r1):
    out = r1.vtysh_cmd("show babel route")
    return sum(1 for ln in out.splitlines() if " metric " in ln)


def babeld_alive(r1):
    out = r1.vtysh_cmd("show babel parameters")
    return len(out.strip()) > 0


def babeld_log_path(tgen):
    return os.path.join(tgen.logdir, "r1", "babeld.log")


class LogWatch:
    "Incremental needle counter for r1's babeld.log"

    def __init__(self, tgen, needle):
        self.path = babeld_log_path(tgen)
        self.needle = needle.encode()
        try:
            self.off = os.path.getsize(self.path)
        except OSError:
            self.off = 0
        self.count = 0

    def poll(self):
        try:
            with open(self.path, "rb") as fp:
                fp.seek(self.off)
                blob = fp.read()
        except OSError:
            return self.count
        idx = blob.rfind(b"\n")
        if idx < 0:
            return self.count
        chunk = blob[: idx + 1]
        self.off += idx + 1
        self.count += chunk.count(self.needle)
        return self.count


def inject(h1, kind, **kwargs):
    args = " ".join("--{} {}".format(k, v) for k, v in kwargs.items())
    out = h1.cmd("python3 {}/send_babel.py --iface h1-eth0 --kind {} {}".format(CWD, kind, args))
    logger.info("inject {}: {}".format(kind, out.strip()))
    return out


def test_converge_protocols():
    "Wait for Babel convergence: r1 must see r2 as a neighbour"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_convergence():
        up = [ln for ln in neighbour_lines(r1) if "reach 0000" not in ln]
        if not up:
            return "r1 has no babel neighbour yet"
        return None

    _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
    assert result is None, "r1 failed to establish a babel neighbour"

    global PEER_LL
    peer = [ln for ln in neighbour_lines(r1) if "reach 0000" not in ln]
    PEER_LL = peer[0].split()[1]
    logger.info("r1 neighbours:\n{}".format(r1.vtysh_cmd("show babel neighbor")))


def test_mechanism_growth_and_controls():
    "One source, many next-hops: growth, feasibility controls, persistence"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    # associate the attacker neighbour (one Hello source for all routes)
    inject(h1, "hello", src="fe80::a1", count=3)
    time.sleep(1.0)
    baseline = route_count(r1)
    assert babeld_alive(r1), "babeld not reachable before the mechanism run"

    # 40 routes: one source (RID, 2001:db8:63::/64), 40 distinct next-hops
    watch = LogWatch(tgen, "Received update for " + MECH_STR)
    inject(h1, "routes", src="fe80::a1", prefix=MECH_PREFIX, start=0,
           count=N_MECH, seqno=SEQNO, metric=1, hseq=4)
    _, result = topotest.run_and_expect(
        lambda: watch.poll() >= N_MECH or None, True, count=60, wait=1)
    assert watch.count >= N_MECH, "updates were not processed"
    time.sleep(0.5)
    grown = route_count(r1)
    assert grown == baseline + N_MECH, (
        "40 updates created {} routes (expected {}): feasibility gate or "
        "route creation broken".format(grown - baseline, N_MECH)
    )

    # control: duplicate next-hops are deduplicated by find_route
    inject(h1, "routes", src="fe80::a1", prefix=MECH_PREFIX, start=0,
           count=N_MECH, seqno=SEQNO, metric=1, hseq=5)
    time.sleep(1.0)
    assert route_count(r1) == grown, "duplicate next-hops created routes"

    # control: an older seqno is unfeasible and must not create a route
    inject(h1, "routes", src="fe80::a1", prefix=MECH_PREFIX, start=N_MECH,
           count=1, seqno=SEQNO - 1, metric=1, hseq=6)
    time.sleep(1.0)
    assert route_count(r1) == grown, "older seqno created a route"

    # proof: same seqno with refmetric 65534 is accepted, i.e. the source's
    # metric never left INFINITY on the receive path
    inject(h1, "routes", src="fe80::a1", prefix=MECH_PREFIX, start=N_MECH + 1,
           count=1, seqno=SEQNO, metric=65534, hseq=7)
    time.sleep(1.0)
    huge = route_count(r1)
    assert huge == grown + 1, (
        "same-seqno refmetric 65534 was rejected; src->metric appears to be "
        "finite, the overflow precondition does not hold"
    )

    # control: a retraction for an unknown next-hop creates nothing
    inject(h1, "retract", src="fe80::a1", prefix=MECH_PREFIX, start=N_MECH + 2,
           seqno=SEQNO)
    time.sleep(1.0)
    assert route_count(r1) == huge, "retraction for unknown next-hop created a route"

    # persistence across neighbour-check ticks (routes must not expire and
    # the neighbour must stay up)
    time.sleep(15)
    assert route_count(r1) == huge, "routes expired during the persistence window"
    lines = neighbour_lines(r1)
    assert any("fe80::a1" in ln and "reach 0000" not in ln for ln in lines), (
        "attacker neighbour did not survive neighbour checks:\n{}".format("\n".join(lines))
    )
    assert babeld_alive(r1), "babeld died during the mechanism run"
    # the legitimate peer is still intact
    assert any(PEER_LL in ln and "reach 0000" not in ln for ln in lines), (
        "legit peer neighbour {} lost:\n{}".format(PEER_LL, "\n".join(lines))
    )


def test_boundary_route_count_overflow():
    "65,536 routes for one source must not abort babeld"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    baseline = route_count(r1)
    assert babeld_alive(r1), "babeld not reachable before the boundary run"

    # 65,536 routes for a fresh source (RID, 2001:db8:64::/64): the 16-bit
    # route_count assertion fires exactly at the 65,536th retain_source()
    watch = LogWatch(tgen, "Received update for " + BOUND_STR)
    t0 = time.time()
    inject(h1, "flood", src="fe80::a1", prefix=BOUND_PREFIX, start=0,
           count=N_FULL, seqno=SEQNO, metric=1, per=PER_PACKET, gap=FLOOD_GAP)

    processed = 0
    alive = True
    while time.time() - t0 < 900:
        processed = watch.poll()
        alive = babeld_alive(r1)
        if not alive or processed >= N_FULL:
            break
        time.sleep(2.0)

    logger.info(
        "boundary run: processed {} updates in {:.1f}s, daemon {}".format(
            processed, time.time() - t0, "alive" if alive else "DEAD"
        )
    )
    assert alive, (
        "babeld died after {} processed updates: the 16-bit route_count "
        "assertion fired (65,536 routes for one source)".format(processed)
    )
    assert processed == N_FULL, (
        "only {} of {} updates were processed".format(processed, N_FULL)
    )
    final = route_count(r1)
    assert final == baseline + N_FULL, (
        "route table holds {} routes, expected {}".format(
            final, baseline + N_FULL
        )
    )
    assert babeld_alive(r1), "babeld died at the end of the boundary run"
    lines = neighbour_lines(r1)
    assert any(PEER_LL in ln and "reach 0000" not in ln for ln in lines), (
        "legit peer neighbour {} lost:\n{}".format(PEER_LL, "\n".join(lines))
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
